package passphrase

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const DEFAULT_PASSPHRASE_LENGTH int = 6

//go:embed eff_large_wordlist.txt
var effLargeWordlist string

// EFF Passphare large wordlist from https://www.eff.org/document/passphrase-wordlists

func secureDieRoll(times int) string {
	var s strings.Builder

	for i := 0; i < times; i++ {
		s.WriteString(fmt.Sprintf("%d", secureDiceRoll()))
	}

	return s.String()
}

func secureDiceRoll() int {
	r, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		panic(err)
	}

	return int(r.Int64()) + 1
}

func GeneratePassphrase(length int) string {
	lines := strings.Split(effLargeWordlist, "\n")
	numberToWordMap := make(map[string]string, len(lines))

	for _, line := range lines {
		if parts := strings.Split(line, "\t"); len(parts) >= 2 {
			number := parts[0]
			word := parts[1]
			numberToWordMap[number] = word
		}
	}

	words := []string{}

	for i := 0; i < length; i++ {
		words = append(words, numberToWordMap[secureDieRoll(5)])
	}

	return strings.Join(words, "-")
}

func GetStrength(entropy float64) string {
	var strength string
	switch {
	case entropy < 40:
		strength = "Very Weak"
	case entropy < 80:
		strength = "Weak"
	case entropy < 120:
		strength = "Moderate"
	case entropy < 160:
		strength = "Strong"
	default:
		strength = "Very Strong"
	}
	return strength
}

func CalculateEntropy(length int) float64 {
	return float64(length) * math.Log2(26)
}
