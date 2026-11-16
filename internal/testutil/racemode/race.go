//go:build race

package racemode

// slowdown: the documented upper end of the cost of the race detector is 10 times.
const slowdown = 10
