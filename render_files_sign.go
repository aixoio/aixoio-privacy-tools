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
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
)

func render_files_sign(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Sign", func() {
		file_dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w, err)
			return
		}

		pk_key, err := os.ReadFile(path_key)
		if err != nil {
			show_err(w, err)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			pgp := crypto.PGP()

			priKey, err := crypto.NewPrivateKeyFromArmored(string(pk_key), PGP_PASSWORD)
			if err != nil {
				show_err(w, err)
				return
			}
			signer, err := pgp.Sign().SigningKey(priKey).Detached().New()
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = signer.Sign(file_dat, crypto.Armor)
			}()

			d := dialog.NewCustomWithoutButtons("Signing - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w, err)
				return
			}

			signer.ClearPrivateParams()

			fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w, err)
					return
				}

				_, err = uc.Write(out)
				if err != nil {
					show_err(w, err)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
			fd.SetFileName(path_wid.Text + ".sig")
			fd.Show()
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				key, gerr := rsahelper.ExportPEMStrToPrivKey(pk_key)
				if gerr != nil {
					err = gerr
					return
				}
				out, err = rsahelper.RsaSign(key, file_dat)
			}()

			d := dialog.NewCustomWithoutButtons("Signing - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w, err)
				return
			}

			fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w, err)
					return
				}

				_, err = uc.Write(out)
				if err != nil {
					show_err(w, err)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
			fd.SetFileName(path_wid.Text + ".arsig") // .arsig = aixoio rsa signature
			fd.Show()
		}
	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files - Public key - Sign"),
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
								show_err(w, err)
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
				widget.NewLabel("Private key"),
				container.NewGridWithColumns(
					2,
					path_wid_key,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w, err)
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
