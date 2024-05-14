package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func render_home(w fyne.Window) fyne.CanvasObject {
	about_btn := widget.NewToolbarAction(theme.QuestionIcon(), func() {
		txt := widget.NewRichTextFromMarkdown(`This program is licensed under the MIT license`)

		d := dialog.NewCustom("About aixoio's privacy tools", "Ok", txt, w)
		d.Show()
	})

	return container.NewBorder(
		widget.NewToolbar(widget.NewToolbarSpacer(), about_btn),
		nil,
		nil,
		nil,
		container.NewCenter(
			container.NewGridWithColumns(
				2,
				widget.NewButton("Files", func() {
					w.SetContent(render_files(w))
				}),
				widget.NewButton("Text", func() {
					w.SetContent(render_text(w))
				}),
			),
		),
	)
}
