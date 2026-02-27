#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

mkdir -p .storybook/resolve-imports/mediawiki.ui
mkdir -p .storybook/resolve-imports/assets

rm -f .storybook/resolve-imports/mediawiki.skin.variables.less
cp resources/mediawiki.less/mediawiki.skin.variables.less .storybook/resolve-imports/

# Fetch resources via curl, `-sSL` silently, Show only errors, Location header and also with a 3XX response code.
curl -sS "https://www.mediawiki.org/w/load.php?only=styles&skin=vector&debug=true&modules=ext.echo.styles.badge|ext.uls.pt|wikibase.client.init|mediawiki.skinning.interface|mediawiki.ui.icon|mediawiki.ui.button" -o .storybook/integration.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.skin.defaults.less?format=TEXT" | base64 --decode > .storybook/resolve-imports/mediawiki.skin.defaults.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.less?format=TEXT" | base64 --decode > .storybook/resolve-imports/mediawiki.mixins.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.ui/variables.less?format=TEXT" | base64 --decode > .storybook/resolve-imports/mediawiki.ui/variables.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.rotation.less?format=TEXT" | base64 --decode > .storybook/resolve-imports/mediawiki.mixins.rotation.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.animation.less?format=TEXT" | base64 --decode > .storybook/resolve-imports/mediawiki.mixins.animation.less
curl -sS "https://en.m.wikipedia.org/static/images/mobile/copyright/wikipedia-wordmark-en.svg" -o ".storybook/resolve-imports/assets/wordmark.svg"
curl -sS "https://en.m.wikipedia.org/static/images/mobile/copyright/wikipedia.png" -o ".storybook/resolve-imports/assets/icon.png"
curl -sS "https://en.wikipedia.org/static/images/mobile/copyright/wikipedia-tagline-en.svg" -o ".storybook/resolve-imports/assets/tagline.svg"

# Add less variable support
echo "@msg-parentheses-start: '(';"  >> .storybook/resolve-imports/mediawiki.skin.defaults.less
echo "@msg-parentheses-end: ')';"  >> .storybook/resolve-imports/mediawiki.skin.defaults.less