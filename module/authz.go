package module

import (
	"text/template"

	pgs "github.com/lyft/protoc-gen-star"
	pgsgo "github.com/lyft/protoc-gen-star/lang/go"
	"github.com/ulbqb/protoc-gen-authz/authz"
	"google.golang.org/protobuf/proto"
)

type AuthzModule struct {
	*pgs.ModuleBase
	ctx pgsgo.Context
	tpl *template.Template
}

// RoleTmp returns an initialized RoleTmpPlugin
func Authz() *AuthzModule { return &AuthzModule{ModuleBase: &pgs.ModuleBase{}} }

func (p *AuthzModule) InitContext(c pgs.BuildContext) {
	p.ModuleBase.InitContext(c)
	p.ctx = pgsgo.InitContext(c.Parameters())

	tpl := template.New("authz").Funcs(map[string]interface{}{
		"package":  p.ctx.PackageName,
		"name":     p.ctx.Name,
		"allow":    p.allow,
		"disallow": p.disallow,
		"any":      p.any,
	})

	p.tpl = template.Must(tpl.Parse(authzTpl))
}

// Name satisfies the generator.Plugin interface.
func (p *AuthzModule) Name() string { return "authz" }

func (p *AuthzModule) Execute(targets map[string]pgs.File, pkgs map[string]pgs.Package) []pgs.Artifact {

	for _, t := range targets {
		p.generate(t)
	}

	return p.Artifacts()
}

func (p *AuthzModule) generate(f pgs.File) {
	if len(f.Services()) == 0 {
		return
	}

	name := p.ctx.OutputPath(f).SetExt(".authz.go")
	p.AddGeneratorTemplateFile(name.String(), p.tpl, f)
}

func (p *AuthzModule) allow(m pgs.Method) []string {
	opt := m.Descriptor().Options

	ext := proto.GetExtension(opt, authz.E_Rules)
	opts, ok := ext.(*authz.AuthzRules)
	if ok && opts != nil && len(opts.Allow) > 0 {
		return opts.Allow
	} else {
		return []string{}
	}
}

func (p *AuthzModule) disallow(m pgs.Method) []string {
	opt := m.Descriptor().Options

	ext := proto.GetExtension(opt, authz.E_Rules)
	opts, ok := ext.(*authz.AuthzRules)
	if ok && opts != nil && len(opts.Disallow) > 0 {
		return opts.Disallow
	} else {
		return []string{}
	}
}

func (p *AuthzModule) any(m pgs.Method) bool {
	opt := m.Descriptor().Options

	ext := proto.GetExtension(opt, authz.E_Rules)
	opts, ok := ext.(*authz.AuthzRules)
	if ok && opts != nil {
		return opts.Any
	} else {
		return false
	}
}

const authzTpl = `package {{ package . }}

import "github.com/ulbqb/protoc-gen-authz/authz"

{{ range .Services }}
	{{ $service := . }}
var {{ name $service }}GrantingRoles = map[string]authz.AuthzRules {
	{{- range $service.Methods }}
		{{- $method := . }}
	"{{ name $method }}": {
		Allow: []string{
		{{- range allow $method }}
			"{{ . }}",
		{{- end }}
		},
		Disallow: []string{
		{{- range disallow $method }}
			"{{ . }}",
		{{- end }}
		},
		Any: {{ any $method }},
	},
	{{- end }}
}
func Validate{{ name $service }}Role(methodName string, receivedRoles []string) bool {
	rules, ok := {{ name $service }}GrantingRoles[methodName]
	if !ok {
		return false
	}

	if len(rules.Allow) > 0 {
		return hasIntersectionFor{{ name $service }}(receivedRoles, rules.Allow)
	}

	if len(rules.Disallow) > 0 {
		return !hasIntersectionFor{{ name $service }}(receivedRoles, rules.Disallow)
	}

	return rules.Any
}

//https://installmd.com/c/105/go/intersection-of-two-slices
func hasIntersectionFor{{ name $service }}(a, b []string) bool {
	// uses empty struct (0 bytes) for map values.
	m := make(map[string]struct{}, len(b))

	// cached
	for _, v := range b {
		m[v] = struct{}{}
	}

	var s []string
	for _, v := range a {
		if _, ok := m[v]; ok {
			s = append(s, v)
		}
	}

	return len(s) > 0
}
{{ end }}
`
