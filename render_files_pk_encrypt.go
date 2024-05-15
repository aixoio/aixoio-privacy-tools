package main

import (
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
)

func render_files_pk_encrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Encrypt", func() {
		file_dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w)
			return
		}

		pk_file_dat, err := os.ReadFile(path_key)
		if err != nil {
			show_err(w)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			var out string

			go func() {
				defer wg.Done()
				out, err = helper.EncryptBinaryMessageArmored(string(pk_file_dat), file_dat)
			}()

			d := dialog.NewCustomWithoutButtons("Encrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w)
				return
			}

			dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w)
					return
				}

				_, err = uc.Write([]byte(out))
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			pk_key := rsahelper.ExportPEMStrToPubKey(pk_file_dat)

			go func() {
				defer wg.Done()
				out = rsahelper.Rsa_enc(pk_key, file_dat)
			}()

			d := dialog.NewCustomWithoutButtons("Encrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w)
					return
				}

				_, err = uc.Write(out)
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)

		}

	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files - Public key - Encrypt"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("File"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Public key"),
				container.NewGridWithColumns(
					2,
					path_wid_key,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path_key = uc.URI().Path()
							path_wid_key.SetText(uc.URI().Name())
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Cipher"),
				sel_wid,
			),
		),
	)
}
