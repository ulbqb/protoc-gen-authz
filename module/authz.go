package module

import (
	"fmt"
	"sort"
	"strings"
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
		"package":      p.ctx.PackageName,
		"allow":        p.allow,
		"disallow":     p.disallow,
		"any":          p.any,
		"roles":        p.roles,
		"fullMethod":   p.fullMethod,
		"snakeToCamel": p.snakeToCamel,
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

func (p *AuthzModule) allow(m pgs.Method) []int {
	opt := m.Descriptor().Options
	ext := proto.GetExtension(opt, authz.E_Rules)
	opts, ok := ext.(*authz.AuthzRules)
	if ok && opts != nil && len(opts.Allow) > 0 {
		allow := opts.Allow
		sort.Strings(allow)
		roles := p.roles(m.Service())
		return roleIndexes(roles, allow)
	} else {
		return []int{}
	}
}

func (p *AuthzModule) disallow(m pgs.Method) []int {
	opt := m.Descriptor().Options
	ext := proto.GetExtension(opt, authz.E_Rules)
	opts, ok := ext.(*authz.AuthzRules)
	if ok && opts != nil && len(opts.Disallow) > 0 {
		disallow := opts.Disallow
		sort.Strings(disallow)
		roles := p.roles(m.Service())
		return roleIndexes(roles, disallow)
	} else {
		return []int{}
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

func (p *AuthzModule) roles(m pgs.Service) []string {
	opt := m.Descriptor().Options
	ext := proto.GetExtension(opt, authz.E_Roles)
	roles, ok := ext.([]string)
	if ok && roles != nil && len(roles) > 0 {
		sort.Strings(roles)
		return removeDuplicateValuesOfSlice(roles)
	} else {
		return []string{}
	}
}

func (p *AuthzModule) fullMethod(m pgs.Method) string {
	proto := m.Package().ProtoName().String()
	service := m.Service().Name().String()
	method := m.Name().String()
	return fmt.Sprintf("/%s.%s/%s", proto, service, method)
}

func (p *AuthzModule) snakeToCamel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	n := strings.Builder{}
	n.Grow(len(s))
	capNext := true
	for i, v := range []byte(s) {
		vIsCap := v >= 'A' && v <= 'Z'
		vIsLow := v >= 'a' && v <= 'z'
		if capNext {
			if vIsLow {
				v += 'A'
				v -= 'a'
			}
		} else if i == 0 {
			if vIsCap {
				v += 'a'
				v -= 'A'
			}
		}
		if vIsCap || vIsLow {
			n.WriteByte(v)
			capNext = false
		} else if vIsNum := v >= '0' && v <= '9'; vIsNum {
			n.WriteByte(v)
			capNext = true
		} else {
			capNext = v == '_'
		}
	}
	return n.String()
}

const authzTpl = `package {{ package . }}

import "github.com/ulbqb/protoc-gen-authz/authz"


{{ range .Services }}
	{{ $service := . }}
const (
	{{- range roles $service }}
	{{ $service.Name }}AuthzRole_{{ snakeToCamel . }} = "{{ . }}"
	{{- end }}
)

var {{ $service.Name }}AuthzRoles = []string{
	{{- range roles $service }}
	{{ $service.Name }}AuthzRole_{{ snakeToCamel . }},
	{{- end }}
}

var {{ $service.Name }}AuthzRules = map[string]authz.AuthzRules {
	{{- range $service.Methods }}
		{{- $method := . }}
	"{{ fullMethod $method }}": {
		Allow: []string{
		{{- range allow $method }}
			{{ $service.Name }}AuthzRoles[{{ . }}],
		{{- end }}
		},
		Disallow: []string{
		{{- range disallow $method }}
			{{ $service.Name }}AuthzRoles[{{ . }}],
		{{- end }}
		},
		Any: {{ any $method }},
	},
	{{- end }}
}
func Validate{{ $service.Name }}AuthzRole(methodName string, receivedRoles []string) bool {
	rules, ok := {{ $service.Name }}AuthzRules[methodName]
	if !ok {
		return false
	}

	if len(rules.Allow) > 0 {
		return hasIntersectionFor{{ $service.Name }}Authz(receivedRoles, rules.Allow)
	}

	if len(rules.Disallow) > 0 {
		return !hasIntersectionFor{{ $service.Name }}Authz(receivedRoles, rules.Disallow)
	}

	return rules.Any
}

//https://installmd.com/c/105/go/intersection-of-two-slices
func hasIntersectionFor{{ $service.Name }}Authz(a, b []string) bool {
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
