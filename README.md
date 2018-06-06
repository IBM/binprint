# Continuous Integration Traceability

Traceability is the ability to know exactly what went in to a given build,
release, and/or deployment. Common examples of the sort of information that
falls under this are:

- internal dependencies
- 3rd party dependencies
- open source license obligations
- bug fixes
- security impact of vulnerabilities in dependencies

## The Problem

### In A Perfect World

When a release pipeline is designed and implemented from the start of a project
you can build in the recording of metadata for build/release tracking up front.
You can do this by making use of various CI/CD tools for managing your project
life cycle that require you to use certain build tools that do things like
automatically track dependencies and builds.

You know exactly what is in every release you cut and release you deploy. If a
user gives you the version of your product you know _exactly_ what known bugs
are in it and what has changed since that build.

You don't have any traceability problems and you probably aren't reading this.

### In The Real World

When a CI/CD pipeline grows organically over time from a collection of
components developed by independent teams with their own tool preferences, you
have a traceability problem.

One way to fix this problem is to completely redesign your pipeline from the
ground up and force your previously independent teams to use the tools you've
mandated in order to track everything right from the start. This is often the
kind of rewrite that falls under the "never rewrite your software" rule with a
side helping of complicated human factors around forcing people to change things
they probably feel strongly about.

Another way to fix this is to provide tooling that can be injected in to the
build processes of all of your projects in a way that requires as little change
as possible.

## A Solution

Record everything (_except_ the actual content) and store it all as a massive
graph. Think of it as Facebook for Files with a view of all the places a file
has been seen, where/when it was created, who its parents are, what other files
were in it's graduating class of v1.0.0 at General Availability High, etc.

### Multi-Digest Keyed Metadata

A customer provides you with a sha512sum of the release they are using. They do
this because they work for a defense contractor and aren't even allowed to have
weaker digest tools installed on their computer.

This cannot be mapped to any of your releases unless you're calculating SHA-2
512 digests for all of your files. Fortunately, you use Artifactory which _does_
support this digest. You search and are provided a list of 300 results. Now you
must go through them all to see which one can be traced back to a release
because Artifactory stores the metadata by path rather than digest. You can't
look in Jenkins without finding an Artifactory build record and you can't look
in version control until you find the build that originally produced the file.
And even when you managed to track it back to a Jenkins build you can only hope
that it was recent enough that the build record hasn't been log rotated to
oblivion.

#### Solution

Each file seen has multiple digests calculated for it (in parallel).

- MD5 (`md5sum`)
- SHA1 (`sha1sum`, `shasum -a 1`)
- git SHA1 (`git hash-object -t blob`)
- SHA2-256 (`shasum -a 256`)
- SHA2-384 (`shasum -a 384`)
- SHA2-512 (`shasum -a 512`)

This means that given a digest in _any_ of the supported forms, the file can be
found. Additionally, that digest can be mapped to the other digests of that same
file. When a web developer gives you the sha-384 SRI string for a file (because
that's what Mozilla recommends for SRI), you can immediately map that back to
Jenkins via the corresponding md5sum, to Artifactory via the sha-512 digest, or
even directly to git if the file is distributed as-is from source control.

#### Background

A cryptographic digest of every file seen allows for reliable identification of
files even if they are renamed. Historically this was done with MD5 (`md5sum`,
which Jenkins still uses), but it was deemed _more than 2 decades ago_. The
popular successor to MD5 was SHA-1 (`sha1sum`, `git`), which has only been
considered insecure for _less than a decade_. All current best practices require
the use of SHA-2 (typically sha256, sha384, or sha512) or SHA-3 for such
applications.

For the purposes of identifying files, however, where the concern is more about
accidental collisions than _intentional_ collisions (aka, a collision attack).
Because of this the ideal digest algorithm is more a function of the number of
files that need to be uniquely identified. This is how Jenkins still manages to
get by with MD5 for the most part. Larger file collections, however, often have
coincidental md5 collisions which renders the digest useless as a single key.

Git uses SHA1 internally (which has caused some criticism from the security
community), however it does _not_ use a bare SHA1 digest of the file contents as
the documentation may suggest. In order to provide additional protection from
collisions, every object in git (blobs, trees, commits, etc.) has its digest
calculated with both the type **and** the length of the data prefixed. While
this does mitigate a lot of the security concerns with using SHA1, the larger
implication for our purposes is that we have to calculate 2 different SHA1
digests for each file if we want to be able to correlate a file to a git
repository or commit.

## FAQ

### Doesn't Artifactory support metadata like this already?

**Yes, but** only on file paths, not the file content. If you copy a file (which
is essentially an alias because of de-duplication), you do not copy the
metadata. That means if you copy a build to a release folder you can't ask
Artifactory for the metadata that was added to the build.

### Doesn't Jenkins track all of this for you with fingerprints?

**Yes, but** you are required to keep all of your build history forever, and
still won't know anything about your _external_ dependencies.
