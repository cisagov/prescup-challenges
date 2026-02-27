#!/usr/bin/env bash
set -eu

mkdir -p .resolve-less-imports/images
mkdir -p .resolve-less-imports/mediawiki.ui

# Copy skin's mediawiki.skin.variables.less to use it over core's own, which is removed.
rm -f .resolve-less-imports/mediawiki.skin.variables.less
cp resources/mediawiki.less/mediawiki.skin.variables.less .resolve-less-imports/

# Fetch resources via curl, `-sSL` silently, Show only errors, Location header and also with a 3XX response code.
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.skin.defaults.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.skin.defaults.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.skin.defaults.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.skin.variables.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.mixins.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.ui/variables.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.ui/variables.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.rotation.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.mixins.rotation.less
curl -sSL "https://gerrit.wikimedia.org/r/plugins/gitiles/mediawiki/core/+/master/resources/src/mediawiki.less/mediawiki.mixins.animation.less?format=TEXT" | base64 --decode > .resolve-less-imports/mediawiki.mixins.animation.less

curl "https://en.wikipedia.org/w/load.php?modules=mediawiki.ui.icon&only=styles&debug=true&useskin=minerva" -o .resolve-less-imports/mediawiki.ui.icons.less
# Append compatibility with wgMinervaApplyKnownTemplateHacks.
echo "@wgMinervaApplyKnownTemplateHacks: 1;"  >> .resolve-less-imports/mediawiki.ui/variables.less

# clock icon
curl "https://en.m.wikipedia.org/w/load.php?modules=skins.minerva.icons.wikimedia&image=history&format=original&skin=minerva&version=7aa66" -o .resolve-less-imports/images/clock.svg

# expand icon
curl "https://en.m.wikipedia.org/w/load.php?modules=mobile.ooui.icons&image=expand&&format=rasterized&skin=minerva&version=grblv" -o .resolve-less-imports/images/expand.svg
