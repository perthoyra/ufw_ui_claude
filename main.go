// Command ufwgui is a graphical front end for the Uncomplicated Firewall (ufw).
package main

import (
	"os"

	"fyne.io/fyne/v2/app"

	"ufwgui/internal/ufw"
	"ufwgui/internal/ui"
)

func main() {
	priv := ufw.PrivPkexec
	if os.Geteuid() == 0 {
		priv = ufw.PrivNone
	}
	a := app.NewWithID("local.ufwgui")
	ui.New(a, priv).ShowAndRun()
}
