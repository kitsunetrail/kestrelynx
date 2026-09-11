"""Map Material's hreflang tags and language selector to translated pages.

Translations share a source path, optionally with a language suffix before
the extension (for example, articles/example.md and articles/example-ja.md).
Each extra.alternate entry supplies its source docs_dir and published root.
"""

from pathlib import Path, PurePosixPath
from urllib.parse import urljoin

from mkdocs.structure.files import File


def _with_alternates(context, config, alternates):
    # Keep the global language roots intact for subsequent page renders.
    return {
        **context,
        "config": {**config, "extra": {**config.extra, "alternate": alternates}},
    }


def on_page_context(context, *, page, config, nav):
    root = Path(config.config_file_path).resolve().parent
    source = PurePosixPath(page.file.src_uri)
    language = config.theme["language"]
    stem = source.stem.removesuffix(f"-{language}")
    base = source.with_stem(stem)
    alternates = []

    for alternate in config.extra.get("alternate", []):
        docs_dir = root / alternate["docs_dir"]
        if alternate["lang"] == language:
            candidates = [source]
        else:
            candidates = [base, base.with_stem(f"{stem}-{alternate['lang']}")]

        for candidate in candidates:
            if not (docs_dir / candidate).is_file():
                continue
            target = File(
                candidate.as_posix(), str(docs_dir), config.site_dir,
                config.use_directory_urls,
            )
            alternates.append({
                **alternate,
                "link": urljoin(alternate["link"], target.url),
            })
            break

    return _with_alternates(context, config, alternates)


def on_template_context(context, *, template_name, config):
    # Static templates such as 404.html have no translated content page.
    return _with_alternates(context, config, [])
