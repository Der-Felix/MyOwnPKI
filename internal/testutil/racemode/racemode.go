// Package racemode scales the time limits of tests that run under the race detector.
//
// A limit such as "one fuzz input may take 2 seconds" guards against an input that stalls the server (a
// quadratic loop takes minutes). The race detector makes ordinary work 2 to 20 times slower, and on a busy CI runner
// a correct program then misses the limit. Scale keeps the limit as it is in a normal run, where the guard has to be
// sharp, and widens it under -race, where it only has to catch a hang.
package racemode

import "time"

// Scale returns d, or d times the slowdown that the race detector causes when the test binary is built with -race.
func Scale(d time.Duration) time.Duration { return d * slowdown }
