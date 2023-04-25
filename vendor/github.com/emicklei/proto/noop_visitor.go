// Copyright (c) 2022 Ernest Micklei
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package proto

// NoopVisitor is a no-operation visitor that can be used when creating your own visitor that is interested in only one or a few types.
// It implements the Visitor interface.
type NoopVisitor struct{}

func (n NoopVisitor) VisitMessage(m *Message)         {}
func (n NoopVisitor) VisitService(v *Service)         {}
func (n NoopVisitor) VisitSyntax(s *Syntax)           {}
func (n NoopVisitor) VisitPackage(p *Package)         {}
func (n NoopVisitor) VisitOption(o *Option)           {}
func (n NoopVisitor) VisitImport(i *Import)           {}
func (n NoopVisitor) VisitNormalField(i *NormalField) {}
func (n NoopVisitor) VisitEnumField(i *EnumField)     {}
func (n NoopVisitor) VisitEnum(e *Enum)               {}
func (n NoopVisitor) VisitComment(e *Comment)         {}
func (n NoopVisitor) VisitOneof(o *Oneof)             {}
func (n NoopVisitor) VisitOneofField(o *OneOfField)   {}
func (n NoopVisitor) VisitReserved(r *Reserved)       {}
func (n NoopVisitor) VisitRPC(r *RPC)                 {}
func (n NoopVisitor) VisitMapField(f *MapField)       {}

// proto2
func (n NoopVisitor) VisitGroup(g *Group)           {}
func (n NoopVisitor) VisitExtensions(e *Extensions) {}
