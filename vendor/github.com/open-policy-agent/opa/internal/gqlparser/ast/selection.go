package ast

type SelectionSet []Selection

type Selection interface {
	isSelection()
	GetPosition() *Position
}

func (*Field) isSelection()          {}
func (*FragmentSpread) isSelection() {}
func (*InlineFragment) isSelection() {}

func (s *Field) GetPosition() *Position          { return s.Position }
func (s *FragmentSpread) GetPosition() *Position { return s.Position }
func (s *InlineFragment) GetPosition() *Position { return s.Position }

type Field struct {
	Alias        string
	Name         string
	Arguments    ArgumentList
	Directives   DirectiveList
	SelectionSet SelectionSet
	Position     *Position `dump:"-" json:"-"`

	// Require validation
	Definition       *FieldDefinition
	ObjectDefinition *Definition
}

type Argument struct {
	Name     string
	Value    *Value
	Position *Position `dump:"-" json:"-"`
}

func (s *Field) ArgumentMap(vars map[string]interface{}) map[string]interface{} {
	return arg2map(s.Definition.Arguments, s.Arguments, vars)
}
