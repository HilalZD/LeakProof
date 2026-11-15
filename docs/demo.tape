# VHS script for the README demo GIF (https://github.com/charmbracelet/vhs).
#
# Before recording:
#   1. Check out NoteNest's broken branch:
#        cd ../notenest-three-and-free && git checkout broken   (NoteNest next to the LeakProof folder)
#   2. From the LeakProof folder, run:  vhs docs/demo.tape
#   3. The GIF lands in docs/demo.gif. Swap it in for the placeholder line in README.md.
#
# npx downloads @leakproof/cli from npm, so v0.2.0 has to be published first.
# To record before publishing, replace the Type line with:
#   Type "node ../LeakProof/dist/index.js"

Output docs/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 820
Set Padding 20
Set Theme "GitHub Dark"
Set TypingSpeed 60ms

Hide
# Warm up npx so its "Ok to proceed?" prompt never shows on camera.
Type "cd ../notenest-three-and-free && npx --yes @leakproof/cli --version && clear"
Enter
Sleep 8s
Show

Sleep 500ms
Type "npx @leakproof/cli"
Sleep 500ms
Enter

# The report is ~100 lines, so the terminal ends on the HIGH/MEDIUM findings,
# the fix link and the footer. Hold there so viewers can read it.
Sleep 8s
