package main

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
	"github.com/google/uuid"
)

func render_folder_pk_encrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Encrypt", func() {

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
			var gerr error = nil

			go func() {
				defer wg.Done()

				/* TODO: Read folder and compress to zip
				   Encrypt zip
				   Save encrypted zip */
				tmpZipFile, err := os.CreateTemp("", "apitpgpfolderzip"+uuid.NewString())
				if err != nil {
					gerr = err
					return
				}
				defer tmpZipFile.Close()
				defer os.Remove(tmpZipFile.Name())

				w := zip.NewWriter(tmpZipFile)

				err = filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}

					if info.IsDir() {
						return nil
					}

					relPath, err := filepath.Rel(path, file)
					if err != nil {
						return err
					}

					f, err := w.Create(relPath)
					if err != nil {
						return err
					}

					data, err := os.Open(file)
					if err != nil {
						return err
					}
					defer data.Close()

					_, err = io.Copy(f, data)
					if err != nil {
						return err
					}

					return nil
				})
				if err != nil {
					gerr = err
					return
				}

				// Ensure the zip writer is closed before reading the file
				err = w.Close()
				if err != nil {
					gerr = err
					return
				}

				dat, err := os.ReadFile(tmpZipFile.Name())
				if err != nil {
					gerr = err
					return
				}

				out, err = helper.EncryptBinaryMessageArmored(string(pk_file_dat), dat)
				if err != nil {
					gerr = err
					return
				}
			}()

			d := dialog.NewCustomWithoutButtons("Encrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if gerr != nil {
				show_err(w)
				return
			}

			fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
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
			fd.SetFileName(path_wid.Text + ".zip.gpg")
			fd.Show()
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte
			var gerr error = nil

			pk_key, err := rsahelper.ExportPEMStrToPubKey(pk_file_dat)
			if err != nil {
				show_err(w)
				return
			}

			go func() {
				defer wg.Done()

				/* TODO: Read folder and compress to zip
				   Encrypt zip
				   Save encrypted zip */
				tmpZipFile, err := os.CreateTemp("", "apitrsafolderzip"+uuid.NewString())
				if err != nil {
					gerr = err
					return
				}
				defer tmpZipFile.Close()
				defer os.Remove(tmpZipFile.Name())

				w := zip.NewWriter(tmpZipFile)

				err = filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}

					if info.IsDir() {
						return nil
					}

					relPath, err := filepath.Rel(path, file)
					if err != nil {
						return err
					}

					f, err := w.Create(relPath)
					if err != nil {
						return err
					}

					data, err := os.Open(file)
					if err != nil {
						return err
					}
					defer data.Close()

					_, err = io.Copy(f, data)
					if err != nil {
						return err
					}

					return nil
				})
				if err != nil {
					gerr = err
					return
				}

				// Ensure the zip writer is closed before reading the file
				err = w.Close()
				if err != nil {
					gerr = err
					return
				}

				dat, err := os.ReadFile(tmpZipFile.Name())
				if err != nil {
					gerr = err
					return
				}

				out, gerr = rsahelper.RsaEncrypt(pk_key, dat)
			}()

			if gerr != nil {
				show_err(w)
				return
			}

			d := dialog.NewCustomWithoutButtons("Encrypting - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			fd := dialog.NewFileSave(func(uc fyne.URIWriteCloser, err error) {
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
			fd.SetFileName(path_wid.Text + ".afrsa") // .arsa = aixoio folders rsa
			fd.Show()

		}

	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Folders - Public key - Encrypt"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Folder"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select Folder", func() {
						dialog.ShowFolderOpen(func(uc fyne.ListableURI, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path = uc.Path()
							path_wid.SetText(uc.Name())
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
