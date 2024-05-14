package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_text_encrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	pwd_wid := widget.NewPasswordEntry()
	opts := []string{"AES-256 Bit GCM with SHA256", "AES-256 Bit CBC with SHA256"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	msg_in := widget.NewMultiLineEntry()

	actbtn := widget.NewButton("Encrypt", func() {

	})
	actbtn.Disable()

	msg_in.OnChanged = func(s string) {
		if len(s) != 0 && len(pwd_wid.Text) != 0 {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	pwd_wid.OnChanged = func(s string) {
		if len(s) != 0 && len(msg_in.Text) != 0 {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Text - Encrypt"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Password"),
				pwd_wid,
				widget.NewLabel("Cipher"),
				sel_wid,
				widget.NewLabel("Message"),
				msg_in,
			),
		),
	)

}
