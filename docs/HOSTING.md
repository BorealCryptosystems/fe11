# Documentation hosting

The documentation site uses GitHub Pages at
[borealcryptosystems.github.io/fe11](https://borealcryptosystems.github.io/fe11/).
Versioned directories contain the guides and the four-crate API reference. For
0.1.1, the API entry is `0.1.1/api/index.html` and the How To entry is
`0.1.1/library/docs/how-to/index.html`.

## Build the site

Use Python 3.11 or later and Rustdoc. Generate the four-crate API tree as described
in [API-REFERENCE.md](../API-REFERENCE.md), then assemble it with the guides:

```text
python docs/build_site.py --api-dir API_DIRECTORY --output NEW_SITE_DIRECTORY --previous-site PREVIOUS_SITE_DIRECTORY
```

The API directory contains `index.html`, `fe11/`, `fe11_sys/`,
`fe11_verify_engine_api/` and `fe11_verify_engine/`. The builder copies that tree
and renders repository Markdown using Rustdoc. Its inputs are trusted repository
content. Keep the output outside the source, API and previous-site input trees. The
previous site supplies the unchanged 0.1.0 directory; the new root selector
links both versions. Companion packages retain their 0.1.0 API version.

Open `NEW_SITE_DIRECTORY/index.html` to browse the site locally. Check navigation,
source links, examples and the displayed API contracts. The Rust recipe library
can be type-checked with `cargo check -p fe11 --example how_to`.

## Package the HTML

Archive the site's regular files at ZIP root as `fe11-0.1.1-docs-site.zip`.
Include no directory entries, symbolic links or hidden paths. Record the ZIP's
SHA-256, number of files and total uncompressed bytes in `docs/site-manifest.json`.
That manifest remains outside the archive so its digest is not self-referential.
Update the identity whenever the site's content changes.

Validate and extract the archive with the same tool used by the deployment workflow:

```text
python docs/unpack_site.py --manifest docs/site-manifest.json --archive fe11-0.1.1-docs-site.zip --output NEW_EXTRACTED_SITE
```

Compare the extracted member hashes with the generated directory. The extraction
requires the recorded archive identity, confines every path and accepts regular
files and directories only. The site archive itself contains files only.

## Deploy with GitHub Pages

1. Protect the repository's `main` branch and changes to its workflow and manifest.
2. Configure Pages to use GitHub Actions. Configure the `github-pages` environment
   with a required maintainer reviewer and deployments restricted to `main`.
3. Attach the matching documentation ZIP to the `v0.1.1` GitHub release.
4. Dispatch **Publish documentation** from `main` and approve its environment job.
5. Check the versioned API and How To links on the hosted site.

The workflow downloads the named release asset, checks its digest and inventory,
and deploys the extracted HTML. It is triggered manually. Repository reads are
limited to `contents: read`; only the deployment job receives `pages: write` and
`id-token: write`. Action dependencies are pinned by commit. Environment approval
is configured in repository settings, separately from the YAML workflow.

The Pages upload action excludes hidden paths. Actions-based deployment consumes
the static HTML artifact directly, so this site needs no `.nojekyll` marker.

## Update documentation

Retain versioned directories when adding a release. Update the landing page,
archive manifest and workflow release selector together. To restore an earlier
site, deploy its archive with the corresponding manifest. This operation changes
documentation independently of library packages.

References: [GitHub Pages workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
and [Rustdoc command-line arguments](https://doc.rust-lang.org/rustdoc/command-line-arguments.html).
