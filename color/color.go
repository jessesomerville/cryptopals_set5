package color

import "fmt"

const (
	reset = "\x1b[0m"
	red   = "\x1b[0m"
	blue  = "\x1b[0m"
	green = "\x1b[0m"
)

func Red(s string, vals ...any) {
	fmt.Printf(red+s+reset, vals...)
}

func Blue(s string, vals ...any) {
	fmt.Printf(blue+s+reset, vals...)
}

func Green(s string, vals ...any) {
	fmt.Printf(green+s+reset, vals...)
}
