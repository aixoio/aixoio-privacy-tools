package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_key_generator(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_home(w)) })
	opts := []string{"PGP Elliptic-Curve Curve25519 x25519", "PGP RSA/RSA 4096", "RSA 4096"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Key generator"),
			widget.NewLabel(""),
		),
		widget.NewButton("Generate key pair", func() {

		}),
		nil,
		nil,
		container.New(
			layout.NewFormLayout(),
			widget.NewLabel("Key type"),
			sel_wid,
		),
	)
}
