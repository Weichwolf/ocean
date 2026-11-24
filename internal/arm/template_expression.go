package arm

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type templateBindings struct {
	scope      SubscriptionScope
	group      string
	location   string
	parameters map[string]string
}

func (b templateBindings) evaluate(value string) (string, error) {
	if !strings.HasPrefix(value, "[") {
		return value, nil
	}
	if len(value) > 2048 || !strings.HasSuffix(value, "]") {
		return "", errors.New("invalid template expression")
	}
	p := expressionParser{input: value[1 : len(value)-1], bindings: b}
	result, err := p.expression(0)
	if err == nil && (len(result) > 2048 || strings.TrimSpace(p.input) != "") {
		err = errors.New("invalid template expression result or trailing content")
	}
	return result, err
}

type expressionParser struct {
	input    string
	bindings templateBindings
}

func (p *expressionParser) take(token string) bool {
	p.input = strings.TrimSpace(p.input)
	if !strings.HasPrefix(p.input, token) {
		return false
	}
	p.input = p.input[len(token):]
	return true
}

func (p *expressionParser) expression(depth int) (string, error) {
	if depth > 12 {
		return "", errors.New("template expression nesting limit exceeded")
	}
	if p.take("'") {
		var value strings.Builder
		for {
			part, rest, found := strings.Cut(p.input, "'")
			if !found {
				return "", errors.New("unterminated template string")
			}
			value.WriteString(part)
			p.input = rest
			if !strings.HasPrefix(rest, "'") {
				return value.String(), nil
			}
			value.WriteByte('\'')
			p.input = rest[1:]
		}
	}
	end := strings.IndexByte(p.input, '(')
	if end <= 0 {
		return "", errors.New("expected a template function or quoted string")
	}
	name := strings.ToLower(strings.TrimSpace(p.input[:end]))
	p.input = p.input[end+1:]
	var args []string
	if !p.take(")") {
		for {
			value, err := p.expression(depth + 1)
			if err != nil {
				return "", err
			}
			args = append(args, value)
			if p.take(")") {
				break
			}
			if len(args) >= 8 || !p.take(",") {
				return "", errors.New("invalid template function arguments")
			}
		}
	}
	switch name {
	case "parameters":
		if len(args) == 1 {
			if value, ok := p.bindings.parameters[args[0]]; ok {
				return value, nil
			}
		}
	case "resourcegroup":
		if len(args) == 0 && p.take(".location") {
			return p.bindings.location, nil
		}
	case "format":
		if len(args) >= 2 {
			return formatTemplate(args[0], args[1:])
		}
	case "resourceid":
		if len(args) >= 2 {
			path, err := networkTemplateAddress(p.bindings.group, args[0], strings.Join(args[1:], "/"))
			if err == nil && strings.Count(args[0], "/") == len(args)-1 {
				return path.ID(p.bindings.scope), nil
			}
		}
	}
	return "", fmt.Errorf("unsupported template function or arguments for %q", name)
}

func formatTemplate(pattern string, args []string) (string, error) {
	var text strings.Builder
	for pattern != "" {
		index := strings.IndexAny(pattern, "{}")
		if index < 0 {
			text.WriteString(pattern)
			break
		}
		text.WriteString(pattern[:index])
		if pattern[index] != '{' {
			return "", errors.New("invalid template format placeholder")
		}
		value, rest, found := strings.Cut(pattern[index+1:], "}")
		arg, err := strconv.Atoi(value)
		if !found || err != nil || len(value) != 1 || arg < 0 || arg >= len(args) {
			return "", errors.New("invalid template format placeholder")
		}
		text.WriteString(args[arg])
		if text.Len() > 2048 {
			return "", errors.New("template format result is too large")
		}
		pattern = rest
	}
	return text.String(), nil
}
