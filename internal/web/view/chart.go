package view

// ChartKind is the shape of a server-rendered chart (docs/PHASE3.md D1).
type ChartKind string

// Chart kinds. Vertical kinds draw one column per category, horizontal kinds
// one bar per category.
const (
	// ChartColumns: one value per category; the series of the category
	// gives the color ("this week starts in the warning window").
	ChartColumns ChartKind = "columns"
	// ChartStacked: one value per series in every category, stacked.
	ChartStacked ChartKind = "stacked"
	// ChartBars: horizontal, one value per category.
	ChartBars ChartKind = "bars"
	// ChartStackedBars: horizontal, one value per series, stacked.
	ChartStackedBars ChartKind = "stackedbars"
)

// ChartClass picks the color of a series. The status classes use the fixed
// status tokens (ADR-12); the three series classes are for data that has no
// status meaning (issuances by source) and carry a hatch pattern from the
// second one on, so color is never the only carrier.
type ChartClass string

// Chart classes.
const (
	ChartOK      ChartClass = "ok"
	ChartWarn    ChartClass = "warn"
	ChartCrit    ChartClass = "crit"
	ChartInfo    ChartClass = "info"
	ChartNeutral ChartClass = "neutral"
	ChartS1      ChartClass = "s1"
	ChartS2      ChartClass = "s2"
	ChartS3      ChartClass = "s3"
)

// ChartSeries is one legend entry: a text label and a color class.
type ChartSeries struct {
	Label string
	Class ChartClass
}

// ChartCategory is one column or bar (a week, a CA, an agent state).
type ChartCategory struct {
	// Label is the short text on the axis; Name the longer text for the
	// numbers table and the tooltip (defaults to Label).
	Label, Name string
	// Series is the index of the series that colors a category of the
	// kinds ChartColumns and ChartBars; the stacked kinds ignore it.
	Series int
	// Values: one value for ChartColumns and ChartBars, one per series for
	// the stacked kinds. Negative values count as zero.
	Values []int64
}

// Chart is the plain description of a chart. Every string may be
// attacker-controlled (CA names come from operators, host names from agents):
// the component writes all of them through templ's escaping and clips them.
// The numbers of Values are the only input to the geometry.
type Chart struct {
	// ID is a constant of the calling page, not data: it builds the element
	// ids of the title and description (characters outside a-z, 0-9 and "-"
	// are dropped).
	ID   string
	Kind ChartKind
	// Title is the caption; Summary is the one sentence that tells what the
	// chart says (also the description for screen readers).
	Title, Summary string
	// Empty is shown instead of the chart when every value is zero.
	Empty string
	// CategoryHeader and ValueHeader head the numbers table (the value
	// column of the stacked kinds is one column per series, plus "Total").
	CategoryHeader, ValueHeader string
	// SeriesHeader adds a column to the table of the non-stacked kinds that
	// names the series of every category ("Window"): the same fact the color
	// shows, as text.
	SeriesHeader string
	// Legend draws the series as swatch plus text below the plot.
	Legend     bool
	Series     []ChartSeries
	Categories []ChartCategory
}
