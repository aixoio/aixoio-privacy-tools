package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_steganography(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_home(w)) })

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Steganography"),
			widget.NewLabel(""),
		),
		nil,
		nil,
		nil,
		container.NewCenter(
			container.NewGridWithRows(
				3,
				widget.NewLabel("Stegano: github.com/scott-mescudi/stegano"),
				container.NewGridWithColumns(
					2,
					widget.NewButton("Image Embedding", func() {
						w.SetContent(render_stegano_image_embed(w))
					}),
					widget.NewButton("Image Extracting", func() {
						w.SetContent(render_stegano_image_extract(w))
					}),
				),
				container.NewGridWithColumns(
					2,
					widget.NewButton("Audio Embedding", func() {
						w.SetContent(render_stegano_audio_embed(w))
					}),
					widget.NewButton("Audio Extracting", func() {
						w.SetContent(render_stegano_audio_extract(w))
					}),
				),
			),
		),
	)
}
