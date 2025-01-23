package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/asconhelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
)

func render_files_decrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	pwd_wid := widget.NewPasswordEntry()
	opts := []string{"AES-256 Bit GCM with SHA256", "AES-256 Bit CBC with SHA256", "AGE with Passhprase", "Ascon 128-bit with SHA256 truncated", "Ascon80pq 160-bit with SHA256 truncated"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Decrypt", func() {
		dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w, err)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // GCM
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = aes.AesGCMDecrypt(pwd, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
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
			fd.SetFileName(strings.Replace(path_wid.Text, ".aagcm", "", 1))
			fd.Show()
		case 1: // CBC
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = aes.AesCBCDecrypt(pwd, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
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
			fd.SetFileName(strings.Replace(path_wid.Text, ".aacbc", "", 1))
			fd.Show()
		case 2: // AGE
			sid, err := age.NewScryptIdentity(pwd_wid.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte
			var encErr error

			go func() {
				defer wg.Done()
				reader, err := age.Decrypt(bytes.NewReader(dat), sid)
				if err != nil {
					encErr = err
					return
				}
				out, err = io.ReadAll(reader)
				if err != nil {
					encErr = err
					return
				}

			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if encErr != nil {
				show_err(w, encErr)
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
			fd.SetFileName(strings.Replace(path_wid.Text, ".age", "", 1))
			fd.Show()
		case 3: // Ascon
			pwd := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconDecrypt(pwd, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
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
			fd.SetFileName(strings.Replace(path_wid.Text, ".aas", "", 1))
			fd.Show()
		case 4: // Ascon80pq
			pwd := hashing.Sha256_to_bytes_160bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconDecrypt(pwd, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - "+path_wid.Text, container.NewPadded(
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
			fd.SetFileName(strings.Replace(path_wid.Text, ".aa80pq", "", 1))
			fd.Show()
		}

	})
	actbtn.Disable()

	pwd_wid.OnChanged = func(s string) {
		if len(s) != 0 && path != "" {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files - Decrypt"),
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
							if len(pwd_wid.Text) != 0 && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Password"),
				pwd_wid,
				widget.NewLabel("Cipher"),
				sel_wid,
			),
		),
	)

}
