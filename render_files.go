package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_files(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_home(w)) })

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files"),
			widget.NewLabel(""),
		),
		nil,
		nil,
		nil,
		container.NewCenter(
			container.NewGridWithRows(
				2,
				container.NewGridWithColumns(
					2,
					widget.NewButton("Encrypt", func() {
						w.SetContent(render_files_encrypt(w))
					}),
					widget.NewButton("Decrypt", func() {
						w.SetContent(render_files_decrypt(w))
					}),
				),
				container.NewGridWithColumns(
					2,
					widget.NewButton("Sign", func() {
					}),
					widget.NewButton("Verify", func() {

					}),
				),
			),
		),
	)

}
