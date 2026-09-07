#!/usr/bin/env bash
#
# Assemble angou-gui.app. A .app is just a directory: Contents/MacOS/<exe>,
# Contents/Resources/<icns>, and Contents/Info.plist. Hand-rolled rather than run
# through `fyne package` so the Info.plist can declare the .angou document type
# and carry the build's version and commit, and so `make build-app` needs no tool
# beyond what a stock Mac already has.
#
# The .angou association is declared by filename extension and MIME type, which is
# how the macOS type system matches — it does not read leading-string magic the
# way file(1) and shared-mime-info do, so the ANGOU1 delimiter is not repeated
# here and the format-literal count stays at three (see .claude/CLAUDE.md).

set -euo pipefail

BIN="${1:?usage: make-app.sh <gui-binary> <icns> <version> <commit> <out-dir>}"
ICNS="${2:?usage: make-app.sh <gui-binary> <icns> <version> <commit> <out-dir>}"
VERSION="${3:?}"
COMMIT="${4:?}"
OUTDIR="${5:?}"

APP="$OUTDIR/angou-gui.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

install -m755 "$BIN" "$APP/Contents/MacOS/angou-gui"
install -m644 "$ICNS" "$APP/Contents/Resources/angou.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>angou</string>
	<key>CFBundleDisplayName</key>
	<string>angou</string>
	<key>CFBundleIdentifier</key>
	<string>io.ushineko.angou</string>
	<key>CFBundleExecutable</key>
	<string>angou-gui</string>
	<key>CFBundleIconFile</key>
	<string>angou</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${VERSION}</string>
	<key>CFBundleVersion</key>
	<string>${VERSION}</string>
	<key>AngouCommit</key>
	<string>${COMMIT}</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.utilities</string>
	<key>UTExportedTypeDeclarations</key>
	<array>
		<dict>
			<key>UTTypeIdentifier</key>
			<string>io.ushineko.angou.blob</string>
			<key>UTTypeDescription</key>
			<string>angou encrypted blob</string>
			<key>UTTypeConformsTo</key>
			<array>
				<string>public.data</string>
			</array>
			<key>UTTypeTagSpecification</key>
			<dict>
				<key>public.filename-extension</key>
				<array>
					<string>angou</string>
				</array>
				<key>public.mime-type</key>
				<array>
					<string>application/x-angou-blob</string>
				</array>
			</dict>
		</dict>
	</array>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleTypeName</key>
			<string>angou encrypted blob</string>
			<key>CFBundleTypeRole</key>
			<string>Viewer</string>
			<key>LSHandlerRank</key>
			<string>Owner</string>
			<key>LSItemContentTypes</key>
			<array>
				<string>io.ushineko.angou.blob</string>
			</array>
		</dict>
	</array>
</dict>
</plist>
PLIST

echo "wrote $APP"
