# Record the README GIF with VHS (https://github.com/charmbracelet/vhs):
#   vhs demo.tape   ->  docs/demo.gif
Output docs/demo.gif
Set FontSize 15
Set Width 1300
Set Height 820
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Hide
Type "cd $(mktemp -d) && git init -q && gitghost install >/dev/null && clear" Enter
Show

Type "echo 'OPENAI_KEY = \"sk-proj-Xa91kQ2vB7mN4pL8zR3tY6wE0uI5oH2gF7dS1aZ\"' > config.py" Enter
Sleep 400ms
Type "git add config.py" Enter
Sleep 400ms
Type 'git commit -m "add config"' Enter
Sleep 4s
