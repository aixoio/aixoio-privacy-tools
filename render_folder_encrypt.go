package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
	"github.com/google/uuid"
)

func render_folder_encrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	pwd_wid := widget.NewPasswordEntry()
	opts := []string{"AES-256 Bit GCM with SHA256", "AES-256 Bit CBC with SHA256", "AGE with Passhprase"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Encrypt", func() {

		switch sel_wid.SelectedIndex() {
		case 0: // GCM
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte
			var gerr error = nil

			go func() {
				defer wg.Done()
				/* TODO: Read folder and compress to zip
				   Encrypt zip
				   Save encrypted zip */
				tmpZipFile, err := os.CreateTemp("", "apitaesgcmfolderzip"+uuid.NewString())
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

				out, gerr = aes.AesGCMEncrypt(pwd, dat)
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

				_, err = uc.Write(out)
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)

			fd.SetFileName(path_wid.Text + ".afagcm") // .afagcm = Aixoio Folder AES GCM
			fd.Show()
		case 1: // CBC
			pwd := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte
			var gerr error = nil

			go func() {
				defer wg.Done()
				/* TODO: Read folder and compress to zip
				   Encrypt zip
				   Save encrypted zip */
				tmpZipFile, err := os.CreateTemp("", "apitaescbcfolderzip"+uuid.NewString())
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

				out, gerr = aes.AesCBCEncrypt(pwd, dat)
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

				_, err = uc.Write(out)
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)

			fd.SetFileName(path_wid.Text + ".afacbc") // .afacbc = Aixoio Folder AES CBC
			fd.Show()
		case 2: // AGE
			recip, err := age.NewScryptRecipient(pwd_wid.Text)
			if err != nil {
				show_err(w)
				return
			}

			var wg sync.WaitGroup

			wg.Add(1)

			out := &bytes.Buffer{}
			var gerr error

			go func() {
				defer wg.Done()

				/* TODO: Read folder and compress to zip
				   Encrypt zip
				   Save encrypted zip */
				tmpZipFile, err := os.CreateTemp("", "apitagefolderzip"+uuid.NewString())
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

				writer, err := age.Encrypt(out, recip)
				if err != nil {
					gerr = err
					return
				}

				if _, err := writer.Write(dat); err != nil {
					gerr = err
					return
				}

				if err := writer.Close(); err != nil {
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

				_, err = uc.Write(out.Bytes())
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
			fd.SetFileName(path_wid.Text + ".zip.age") // .age = AGE Standard https://github.com/FiloSottile/age OR age-encryption.org
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
			widget.NewLabel("Folder - Encrypt"),
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
					widget.NewButton("Select folder", func() {
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
