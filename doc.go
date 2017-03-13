package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	swagger "gin-swagger-doc-gen/define"
	"gopkg.in/yaml.v2"

	logger "github.com/cihub/seelog"
)

const (
	ajson  = "application/json"
	axml   = "application/xml"
	aplain = "text/plain"
	ahtml  = "text/html"
)

var pkgCache map[string]struct{} //pkg:controller:function:comments comments: key:value
var controllerComments map[string]string
var importlist map[string]string
var controllerList map[string]map[string]*swagger.Item //controllername Paths items
var modelsList map[string]map[string]swagger.Schema
var rootapi swagger.Swagger
var astPkgs map[string]*ast.Package

//self define
type RouterNode struct {
	init     bool
	isRoot   bool
	nodeName string
	nodePath string
	isLeaf   bool
	subs     []*RouterNode
	parent   *RouterNode
}

var rootNode *RouterNode

func (n *RouterNode) Init() {
	n.init = true
}

func (n *RouterNode) Append(node *RouterNode) {
	if node.init {
		n.subs = append(n.subs, node)
	}
}

func (n *RouterNode) InsertNode(parent string, node *RouterNode) bool {

	if n.isLeaf {
		return false
	}

	if parent == n.nodeName {
		node.parent = n
		n.Append(node)
		return true
	}

	res := false
	for _, v := range n.subs {
		res = res || v.InsertNode(parent, node)
		if res {
			return res
		}
	}
	return res
}

func (n *RouterNode) ExportTree(depth int) {
	for i := 0; i < depth; i++ {
		fmt.Print("-")
	}
	fmt.Print(n.nodeName)
	fmt.Print(("\n"))
	for _, v := range n.subs {
		v.ExportTree(depth + 1)
	}
}

func (n *RouterNode) BindRoot(base string) {
	if n.isLeaf {
		for _, v := range controllerList {
			for k, i := range v {

				r, _ := regexp.Compile("/:([a-zA-Z0-9_]+)")
				key := r.ReplaceAllString(base, "/{${1}}")
				if k == key {
					if rootapi.Paths == nil {
						rootapi.Paths = make(map[string]*swagger.Item)
					}
					rootapi.Paths[key] = i
				}
			}
		}
	} else {
		for _, n := range n.subs {
			n.BindRoot(base + n.nodePath)
		}
	}

}

// refer to builtin.go
var basicTypes = map[string]string{
	"bool":        "boolean:",
	"uint":        "integer:int32",
	"uint8":       "integer:int32",
	"uint16":      "integer:int32",
	"uint32":      "integer:int32",
	"uint64":      "integer:int64",
	"int":         "integer:int64",
	"int8":        "integer:int32",
	"int16:int32": "integer:int32",
	"int32":       "integer:int32",
	"int64":       "integer:int64",
	"uintptr":     "integer:int64",
	"float32":     "number:float",
	"float64":     "number:double",
	"string":      "string:",
	"complex64":   "number:float",
	"complex128":  "number:double",
	"byte":        "string:byte",
	"rune":        "string:byte",
}

func init() {
	pkgCache = make(map[string]struct{})
	controllerComments = make(map[string]string)
	importlist = make(map[string]string)
	controllerList = make(map[string]map[string]*swagger.Item)
	modelsList = make(map[string]map[string]swagger.Schema)
	astPkgs = map[string]*ast.Package{}

	rootNode = new(RouterNode)
	rootNode.init = false
	rootNode.isRoot = true
}

func FileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func parsePackagesFromDir(dirpath string) {
	c := make(chan error)

	go func() {
		filepath.Walk(dirpath, func(fpath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !fileInfo.IsDir() {
				return nil
			}

			if !strings.Contains(fpath, "vendor") && !strings.Contains(fpath, "tests") {
				err = parsePackageFromDir(fpath)
				if err != nil {
					// Send the error to through the channel and continue walking
					c <- fmt.Errorf("Error while parsing directory: %s", err.Error())
					return nil
				}
			}
			return nil
		})
		close(c)
	}()

	//for err := range c {
	//	logger.Warnf("%s", err)
	//}
}

func parsePackageFromDir(path string) error {
	fileSet := token.NewFileSet()
	folderPkgs, err := parser.ParseDir(fileSet, path, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	if err != nil {
		return err
	}

	for k, v := range folderPkgs {
		astPkgs[k] = v
	}

	return nil
}

func generateDocs(routerpath, curpath string) {
	fset := token.NewFileSet()

	f, err := parser.ParseFile(fset, path.Clean(routerpath), nil, parser.ParseComments)
	if err != nil {
		logger.Errorf("Error while parsing router.go: %s", err)
	}

	rootapi.Infos = swagger.Information{}
	rootapi.SwaggerVersion = "2.0"

	// Analyse API comments
	if f.Comments != nil {
		for _, c := range f.Comments {
			for _, s := range strings.Split(c.Text(), "\n") {
				if strings.HasPrefix(s, "@APIVersion") {
					rootapi.Infos.Version = strings.TrimSpace(s[len("@APIVersion"):])
				} else if strings.HasPrefix(s, "@Title") {
					rootapi.Infos.Title = strings.TrimSpace(s[len("@Title"):])
				} else if strings.HasPrefix(s, "@Description") {
					rootapi.Infos.Description = strings.TrimSpace(s[len("@Description"):])
				} else if strings.HasPrefix(s, "@TermsOfServiceUrl") {
					rootapi.Infos.TermsOfService = strings.TrimSpace(s[len("@TermsOfServiceUrl"):])
				} else if strings.HasPrefix(s, "@Contact") {
					rootapi.Infos.Contact.EMail = strings.TrimSpace(s[len("@Contact"):])
				} else if strings.HasPrefix(s, "@Name") {
					rootapi.Infos.Contact.Name = strings.TrimSpace(s[len("@Name"):])
				} else if strings.HasPrefix(s, "@URL") {
					rootapi.Infos.Contact.URL = strings.TrimSpace(s[len("@URL"):])
				} else if strings.HasPrefix(s, "@LicenseUrl") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &swagger.License{URL: strings.TrimSpace(s[len("@LicenseUrl"):])}
					} else {
						rootapi.Infos.License.URL = strings.TrimSpace(s[len("@LicenseUrl"):])
					}
				} else if strings.HasPrefix(s, "@License") {
					if rootapi.Infos.License == nil {
						rootapi.Infos.License = &swagger.License{Name: strings.TrimSpace(s[len("@License"):])}
					} else {
						rootapi.Infos.License.Name = strings.TrimSpace(s[len("@License"):])
					}
				} else if strings.HasPrefix(s, "@Schemes") {
					rootapi.Schemes = strings.Split(strings.TrimSpace(s[len("@Schemes"):]), ",")
				} else if strings.HasPrefix(s, "@Host") {
					rootapi.Host = strings.TrimSpace(s[len("@Host"):])
				}
			}
		}
	}
	// init preset struct
	// analyseControllerPkg(".", presetpath)

	// Analyse controller package
	for _, im := range f.Imports {
		localName := ""
		if im.Name != nil {
			localName = im.Name.Name
		}
		analyseControllerPkg(localName, im.Path.Value, 1)
	}
	for _, d := range f.Decls {
		switch specDecl := d.(type) {
		case *ast.FuncDecl:
			analyseBlockList(specDecl.Body.List)
		}
	}

	//rootNode.ExportTree(0)
	rootNode.BindRoot("")

	os.Mkdir(path.Join(curpath, "swagger"), 0755)
	fd, err := os.Create(path.Join(curpath, "swagger", "swagger.json"))
	fdyml, err := os.Create(path.Join(curpath, "swagger", "swagger.yml"))
	if err != nil {
		panic(err)
	}
	defer fdyml.Close()
	defer fd.Close()
	dt, err := json.MarshalIndent(rootapi, "", "    ")
	dtyml, erryml := yaml.Marshal(rootapi)
	if err != nil || erryml != nil {
		panic(err)
	}
	_, err = fd.Write(dt)
	_, erryml = fdyml.Write(dtyml)
	if err != nil || erryml != nil {
		panic(err)
	}
}

func analyseBlockList(list []ast.Stmt) {
	for _, l := range list {
		switch stmt := l.(type) {
		case *ast.AssignStmt:
			for _, l := range stmt.Rhs {
				if v, ok := l.(*ast.CallExpr); ok {
					selName := v.Fun.(*ast.SelectorExpr).Sel.String()
					xName := v.Fun.(*ast.SelectorExpr).X.(*ast.Ident).String()

					if xName == "gin" && selName == "Default" {
						rootNode.Init()
						rootNode.nodePath = "/"
						rootNode.nodeName = stmt.Lhs[0].(*ast.Ident).String()
					}
					// Analyse NewNamespace, it will return version and the subfunction
					if selName := v.Fun.(*ast.SelectorExpr).Sel.String(); selName != "Group" {
						continue
					}

					parent := v.Fun.(*ast.SelectorExpr).X.(*ast.Ident).String()
					rPath := analyseNewNamespace(v)
					n := new(RouterNode)
					n.Init()
					n.nodeName = stmt.Lhs[0].(*ast.Ident).String()
					n.nodePath = rPath

					res := rootNode.InsertNode(parent, n)
					if !res {
						logger.Errorf("node not match parent:%s,child:%s", parent, n.nodeName)
					}

				}
			}
		case *ast.ExprStmt:
			method := stmt.X.(*ast.CallExpr).Fun
			switch mType := method.(type) {
			case *ast.SelectorExpr:
				selName := mType.Sel.String()
				if selName == "POST" || selName == "PUT" || selName == "GET" {
					nodeName := mType.X.(*ast.Ident).String()
					path, childNode := analyseController(stmt.X.(*ast.CallExpr))

					n := new(RouterNode)
					n.Init()
					n.nodeName = childNode
					n.isLeaf = true
					n.nodePath = path

					rootNode.InsertNode(nodeName, n)
				} else {
					continue
				}

			}
		case *ast.BlockStmt:
			analyseBlockList(stmt.List)
		}
	}
}

// analyseNewNamespace returns version and the others params
func analyseNewNamespace(ce *ast.CallExpr) (first string) {
	for i, p := range ce.Args {
		if i == 0 {
			switch pp := p.(type) {
			case *ast.BasicLit:
				first = strings.Trim(pp.Value, `"`)
			}
			continue
		}
	}
	return
}

func analyseController(ce *ast.CallExpr) (path string, nodeName string) {
	for i, p := range ce.Args {
		if i == 0 {
			switch pp := p.(type) {
			case *ast.BasicLit:
				path = strings.Trim(pp.Value, `"`)
			}
		} else {
			switch pp := p.(type) {
			case *ast.CallExpr:
				logger.Debugf("path:%s has midware", path)
			case *ast.SelectorExpr:
				nodeName = fmt.Sprintf("%s.%s", pp.X.(*ast.Ident).Name, pp.Sel.Name)
			}
		}
	}
	return
}

func analyseNSInclude(baseurl string, ce *ast.CallExpr) string {
	cname := ""
	for _, p := range ce.Args {
		x := p.(*ast.UnaryExpr).X.(*ast.CompositeLit).Type.(*ast.SelectorExpr)
		if v, ok := importlist[fmt.Sprint(x.X)]; ok {
			cname = v + x.Sel.Name
			logger.Debug(cname)
		}
		if apis, ok := controllerList[cname]; ok {
			for rt, item := range apis {
				tag := ""
				if baseurl != "" {
					rt = baseurl + rt
					tag = strings.Trim(baseurl, "/")
				} else {
					tag = cname
				}
				if item.Get != nil {
					item.Get.Tags = []string{tag}
				}
				if item.Post != nil {
					item.Post.Tags = []string{tag}
				}
				if item.Put != nil {
					item.Put.Tags = []string{tag}
				}
				if item.Patch != nil {
					item.Patch.Tags = []string{tag}
				}
				if item.Head != nil {
					item.Head.Tags = []string{tag}
				}
				if item.Delete != nil {
					item.Delete.Tags = []string{tag}
				}
				if item.Options != nil {
					item.Options.Tags = []string{tag}
				}
				if len(rootapi.Paths) == 0 {
					rootapi.Paths = make(map[string]*swagger.Item)
				}
				rt = urlReplace(rt)
				rootapi.Paths[rt] = item
			}
		}
	}
	return cname
}

func analyseControllerPkg(localName, pkgpath string, maxDepth int) {
	pkgpath = strings.Trim(pkgpath, "\"")
	if isSystemPackage(pkgpath) {
		return
	}
	if localName != "" {
		importlist[localName] = pkgpath
	} else {
		pps := strings.Split(pkgpath, "/")
		importlist[pps[len(pps)-1]] = pkgpath
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		logger.Error("GOPATH environment variable is not set or empty")
	}
	pkgRealpath := ""

	wgopath := filepath.SplitList(gopath)
	for _, wg := range wgopath {
		wg, _ = filepath.EvalSymlinks(filepath.Join(wg, "src", pkgpath))
		if FileExists(wg) {
			pkgRealpath = wg
			break
		}
	}
	if pkgRealpath != "" {
		if _, ok := pkgCache[pkgpath]; ok {
			return
		}
		pkgCache[pkgpath] = struct{}{}
	} else {
		logger.Errorf("Package '%s' does not exist in the GOPATH", pkgpath)
	}

	logger.Debugf("pkg real path:%s", pkgRealpath)

	fileSet := token.NewFileSet()
	var err error
	_astPkgs, err := parser.ParseDir(fileSet, pkgRealpath, func(info os.FileInfo) bool {
		name := info.Name()
		return !info.IsDir() && !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go")
	}, parser.ParseComments)
	for k, pkg := range _astPkgs {
		astPkgs[k] = pkg
	}
	if err != nil {
		logger.Errorf("Error while parsing dir at '%s': %s", pkgpath, err)
	}
	for _, pkg := range astPkgs {
		for _, fl := range pkg.Files {
			if maxDepth > 0 {
				for _, im := range fl.Imports {
					localName := ""
					if im.Name != nil {
						localName = im.Name.Name
					}
					analyseControllerPkg(localName, im.Path.Value, maxDepth-1)
				}
			}
			for _, d := range fl.Decls {
				switch specDecl := d.(type) {
				case *ast.FuncDecl:
					// Parse controller method
					parserComments(specDecl.Doc, specDecl.Name.String(), pkgpath)
				case *ast.GenDecl:
					if specDecl.Tok == token.TYPE {
						for _, s := range specDecl.Specs {
							switch tp := s.(*ast.TypeSpec).Type.(type) {
							case *ast.StructType:
								_ = tp.Struct

								// Parse controller definition comments
								if strings.TrimSpace(specDecl.Doc.Text()) != "" {
									controllerComments[pkgpath+s.(*ast.TypeSpec).Name.String()] = specDecl.Doc.Text()
								}
							}
						}
					}
				}
			}
		}
	}
}

func isSystemPackage(pkgpath string) bool {
	goroot := os.Getenv("GOROOT")
	if goroot == "" {
		logger.Errorf("GOROOT environment variable is not set or empty")
	}

	wg, _ := filepath.EvalSymlinks(filepath.Join(goroot, "src", "pkg", pkgpath))
	if FileExists(wg) {
		return true
	}

	//TODO(zh):support go1.4
	wg, _ = filepath.EvalSymlinks(filepath.Join(goroot, "src", pkgpath))
	if FileExists(wg) {
		return true
	}

	return false
}

func peekNextSplitString(ss string) (s string, spacePos int) {
	spacePos = strings.IndexFunc(ss, unicode.IsSpace)
	if spacePos < 0 {
		s = ss
		spacePos = len(ss)
	} else {
		s = strings.TrimSpace(ss[:spacePos])
	}
	return
}

// parse the func comments
func parserComments(comments *ast.CommentGroup, funcName, pkgpath string) error {
	controllerName := ""
	var routerPath string
	var HTTPMethod string
	opts := swagger.Operation{
		Responses: make(map[string]swagger.Response),
	}
	if comments != nil && comments.List != nil {
		for _, c := range comments.List {
			t := strings.TrimSpace(strings.TrimLeft(c.Text, "//"))
			if strings.HasPrefix(t, "@router") {
				elements := strings.TrimSpace(t[len("@router"):])
				e1 := strings.SplitN(elements, " ", 2)
				if len(e1) < 1 {
					return errors.New("you should has router infomation")
				}
				routerPath = e1[0]
				if len(e1) == 2 && e1[1] != "" {
					e1 = strings.SplitN(e1[1], " ", 2)
					HTTPMethod = strings.ToUpper(strings.Trim(e1[0], "[]"))
				} else {
					HTTPMethod = "GET"
				}
			} else if strings.HasPrefix(t, "@Title") {
				opts.OperationID = controllerName + "." + strings.TrimSpace(t[len("@Title"):])
			} else if strings.HasPrefix(t, "@Description") {
				opts.Description = strings.TrimSpace(t[len("@Description"):])
			} else if strings.HasPrefix(t, "@Summary") {
				opts.Summary = strings.TrimSpace(t[len("@Summary"):])
			} else if strings.HasPrefix(t, "@Success") {
				ss := strings.TrimSpace(t[len("@Success"):])
				rs := swagger.Response{}
				respCode, pos := peekNextSplitString(ss)
				ss = strings.TrimSpace(ss[pos:])
				respType, pos := peekNextSplitString(ss)
				if respType == "{object}" || respType == "{array}" {
					isArray := respType == "{array}"
					ss = strings.TrimSpace(ss[pos:])
					schemaName, pos := peekNextSplitString(ss)
					if schemaName == "" {
						logger.Errorf("[%s.%s] Schema must follow {object} or {array}", controllerName, funcName)
					}
					if strings.HasPrefix(schemaName, "[]") {
						schemaName = schemaName[2:]
						isArray = true
					}
					schema := swagger.Schema{}
					if sType, ok := basicTypes[schemaName]; ok {
						typeFormat := strings.Split(sType, ":")
						schema.Type = typeFormat[0]
						schema.Format = typeFormat[1]
					} else {
						m, mod, realTypes := getModel(schemaName)
						schema.Ref = "#/definitions/" + m
						if _, ok := modelsList[pkgpath+controllerName]; !ok {
							modelsList[pkgpath+controllerName] = make(map[string]swagger.Schema, 0)
						}
						modelsList[pkgpath+controllerName][schemaName] = mod
						appendModels(pkgpath, controllerName, realTypes)
					}
					if isArray {
						rs.Schema = &swagger.Schema{
							Type:  "array",
							Items: &schema,
						}
					} else {
						rs.Schema = &schema
					}
					rs.Description = strings.TrimSpace(ss[pos:])
				} else {
					rs.Description = strings.TrimSpace(ss)
				}
				opts.Responses[respCode] = rs
			} else if strings.HasPrefix(t, "@Param") {
				para := swagger.Parameter{}
				p := getparams(strings.TrimSpace(t[len("@Param "):]))
				if len(p) < 4 {
					logger.Error(controllerName + "_" + funcName + "'s comments @Param should have at least 4 params")
				}
				para.Name = p[0]
				switch p[1] {
				case "query":
					fallthrough
				case "header":
					fallthrough
				case "path":
					fallthrough
				case "formData":
					fallthrough
				case "body":
					break
				default:
					//logger.Warnf("[%s.%s] Unknown param location: %s. Possible values are `query`, `header`, `path`, `formData` or `body`.\n", controllerName, funcName, p[1])
				}
				para.In = p[1]
				pp := strings.Split(p[2], ".")
				typ := pp[len(pp)-1]
				if len(pp) >= 2 {
					m, mod, realTypes := getModel(p[2])
					para.Schema = &swagger.Schema{
						Ref: "#/definitions/" + m,
					}
					if _, ok := modelsList[pkgpath+controllerName]; !ok {
						modelsList[pkgpath+controllerName] = make(map[string]swagger.Schema, 0)
					}
					modelsList[pkgpath+controllerName][typ] = mod
					appendModels(pkgpath, controllerName, realTypes)
				} else {
					isArray := false
					paraType := ""
					paraFormat := ""
					if strings.HasPrefix(typ, "[]") {
						typ = typ[2:]
						isArray = true
					}
					if typ == "string" || typ == "number" || typ == "integer" || typ == "boolean" ||
						typ == "array" || typ == "file" {
						paraType = typ
					} else if sType, ok := basicTypes[typ]; ok {
						typeFormat := strings.Split(sType, ":")
						paraType = typeFormat[0]
						paraFormat = typeFormat[1]
						//} else {
						//	logger.Warnf("[%s.%s] Unknown param type: %s\n", controllerName, funcName, typ)
					}
					if isArray {
						para.Type = "array"
						para.Items = &swagger.ParameterItems{
							Type:   paraType,
							Format: paraFormat,
						}
					} else {
						para.Type = paraType
						para.Format = paraFormat
					}
				}
				switch len(p) {
				case 5:
					para.Required, _ = strconv.ParseBool(p[3])
					para.Description = strings.Trim(p[4], `" `)
				case 6:
					para.Default = str2RealType(p[3], para.Type)
					para.Required, _ = strconv.ParseBool(p[4])
					para.Description = strings.Trim(p[5], `" `)
				default:
					para.Description = strings.Trim(p[3], `" `)
				}
				opts.Parameters = append(opts.Parameters, para)
			} else if strings.HasPrefix(t, "@Failure") {
				rs := swagger.Response{}
				st := strings.TrimSpace(t[len("@Failure"):])
				var cd []rune
				var start bool
				for i, s := range st {
					if unicode.IsSpace(s) {
						if start {
							rs.Description = strings.TrimSpace(st[i+1:])
							break
						} else {
							continue
						}
					}
					start = true
					cd = append(cd, s)
				}
				opts.Responses[string(cd)] = rs
			} else if strings.HasPrefix(t, "@Deprecated") {
				opts.Deprecated, _ = strconv.ParseBool(strings.TrimSpace(t[len("@Deprecated"):]))
			} else if strings.HasPrefix(t, "@Accept") {
				accepts := strings.Split(strings.TrimSpace(strings.TrimSpace(t[len("@Accept"):])), ",")
				for _, a := range accepts {
					switch a {
					case "json":
						opts.Consumes = append(opts.Consumes, ajson)
						opts.Produces = append(opts.Produces, ajson)
					case "xml":
						opts.Consumes = append(opts.Consumes, axml)
						opts.Produces = append(opts.Produces, axml)
					case "plain":
						opts.Consumes = append(opts.Consumes, aplain)
						opts.Produces = append(opts.Produces, aplain)
					case "html":
						opts.Consumes = append(opts.Consumes, ahtml)
						opts.Produces = append(opts.Produces, ahtml)
					}
				}
			}
		}
	}
	if routerPath != "" {
		var item *swagger.Item
		if itemList, ok := controllerList[pkgpath+controllerName]; ok {
			if it, ok := itemList[routerPath]; !ok {
				item = &swagger.Item{}
			} else {
				item = it
			}
		} else {
			controllerList[pkgpath+controllerName] = make(map[string]*swagger.Item)
			item = &swagger.Item{}
		}
		switch HTTPMethod {
		case "GET":
			item.Get = &opts
		case "POST":
			item.Post = &opts
		case "PUT":
			item.Put = &opts
		case "PATCH":
			item.Patch = &opts
		case "DELETE":
			item.Delete = &opts
		case "HEAD":
			item.Head = &opts
		case "OPTIONS":
			item.Options = &opts
		}
		controllerList[pkgpath+controllerName][routerPath] = item
	}
	return nil
}

// analisys params return []string
// @Param	query		form	 string	true		"The email for login"
// [query form string true "The email for login"]
func getparams(str string) []string {
	var s []rune
	var j int
	var start bool
	var r []string
	var quoted int8
	for _, c := range []rune(str) {
		if unicode.IsSpace(c) && quoted == 0 {
			if !start {
				continue
			} else {
				start = false
				j++
				r = append(r, string(s))
				s = make([]rune, 0)
				continue
			}
		}

		start = true
		if c == '"' {
			quoted ^= 1
			continue
		}
		s = append(s, c)
	}
	if len(s) > 0 {
		r = append(r, string(s))
	}
	return r
}

func getModel(str string) (objectname string, m swagger.Schema, realTypes []string) {
	strs := strings.Split(str, ".")
	objectname = strs[len(strs)-1]
	packageName := ""
	m.Type = "object"
	for _, pkg := range astPkgs {
		for _, fl := range pkg.Files {
			for k, d := range fl.Scope.Objects {
				if d.Kind == ast.Typ {
					if k != objectname {
						continue
					}
					packageName = pkg.Name
					parseObject(d, k, &m, &realTypes, astPkgs, pkg.Name)
				}
			}
		}
	}
	if m.Title == "" {
		//logger.Warnf("Cannot find the object: %s", str)
		// TODO remove when all type have been supported
		//os.Exit(1)
	}
	if len(rootapi.Definitions) == 0 {
		rootapi.Definitions = make(map[string]swagger.Schema)
	}
	objectname = packageName + "." + objectname
	rootapi.Definitions[objectname] = m
	return
}

func parseObject(d *ast.Object, k string, m *swagger.Schema, realTypes *[]string, astPkgs map[string]*ast.Package, packageName string) {
	ts, ok := d.Decl.(*ast.TypeSpec)
	if !ok {
		logger.Errorf("Unknown type without TypeSec: %v\n", d)
	}
	// TODO support other types, such as `ArrayType`, `MapType`, `InterfaceType` etc...
	st, ok := ts.Type.(*ast.StructType)
	if !ok {
		return
	}
	m.Title = k
	if st.Fields.List != nil {
		m.Properties = make(map[string]swagger.Propertie)
		for _, field := range st.Fields.List {
			realType := ""
			isSlice, realType, sType := typeAnalyser(field)
			if (isSlice && isBasicType(realType)) || sType == "object" {
				if len(strings.Split(realType, " ")) > 1 {
					realType = strings.Replace(realType, " ", ".", -1)
					realType = strings.Replace(realType, "&", "", -1)
					realType = strings.Replace(realType, "{", "", -1)
					realType = strings.Replace(realType, "}", "", -1)
				} else {
					realType = packageName + "." + realType
				}
			}
			*realTypes = append(*realTypes, realType)
			mp := swagger.Propertie{}
			if isSlice {
				mp.Type = "array"
				if isBasicType(realType) {
					typeFormat := strings.Split(sType, ":")
					mp.Items = &swagger.Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				} else {
					mp.Items = &swagger.Propertie{
						Ref: "#/definitions/" + realType,
					}
				}
			} else {
				if sType == "object" {
					mp.Ref = "#/definitions/" + realType
				} else if isBasicType(realType) {
					typeFormat := strings.Split(sType, ":")
					mp.Type = typeFormat[0]
					mp.Format = typeFormat[1]
				} else if realType == "map" {
					typeFormat := strings.Split(sType, ":")
					mp.AdditionalProperties = &swagger.Propertie{
						Type:   typeFormat[0],
						Format: typeFormat[1],
					}
				}
			}
			if field.Names != nil {

				// set property name as field name
				var name = field.Names[0].Name

				// if no tag skip tag processing
				if field.Tag == nil {
					m.Properties[name] = mp
					continue
				}

				var tagValues []string

				stag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))

				defaultValue := stag.Get("doc")
				if defaultValue != "" {
					r, _ := regexp.Compile(`default\((.*)\)`)
					if r.MatchString(defaultValue) {
						res := r.FindStringSubmatch(defaultValue)
						mp.Default = str2RealType(res[1], realType)

						//} else {
						//	logger.Warnf("Invalid default value: %s", defaultValue)
					}
				}

				tag := stag.Get("json")

				if tag != "" {
					tagValues = strings.Split(tag, ",")
				}

				// dont add property if json tag first value is "-"
				if len(tagValues) == 0 || tagValues[0] != "-" {

					// set property name to the left most json tag value only if is not omitempty
					if len(tagValues) > 0 && tagValues[0] != "omitempty" {
						name = tagValues[0]
					}

					if thrifttag := stag.Get("thrift"); thrifttag != "" {
						ts := strings.Split(thrifttag, ",")
						if ts[0] != "" {
							name = ts[0]
						}
					}
					if required := stag.Get("required"); required != "" {
						m.Required = append(m.Required, name)
					}
					if desc := stag.Get("description"); desc != "" {
						mp.Description = desc
					}

					m.Properties[name] = mp
				}
				if ignore := stag.Get("ignore"); ignore != "" {
					continue
				}
			} else {
				for _, pkg := range astPkgs {
					for _, fl := range pkg.Files {
						for nameOfObj, obj := range fl.Scope.Objects {
							if obj.Name == fmt.Sprint(field.Type) {
								parseObject(obj, nameOfObj, m, realTypes, astPkgs, pkg.Name)
							}
						}
					}
				}
			}
		}
	}
}

func typeAnalyser(f *ast.Field) (isSlice bool, realType, swaggerType string) {
	if arr, ok := f.Type.(*ast.ArrayType); ok {
		if isBasicType(fmt.Sprint(arr.Elt)) {
			return false, fmt.Sprintf("[]%v", arr.Elt), basicTypes[fmt.Sprint(arr.Elt)]
		}
		if mp, ok := arr.Elt.(*ast.MapType); ok {
			return false, fmt.Sprintf("map[%v][%v]", mp.Key, mp.Value), "object"
		}
		if star, ok := arr.Elt.(*ast.StarExpr); ok {
			return true, fmt.Sprint(star.X), "object"
		}
		return true, fmt.Sprint(arr.Elt), "object"
	}
	switch t := f.Type.(type) {
	case *ast.StarExpr:
		return false, fmt.Sprint(t.X), "object"
	case *ast.MapType:
		val := fmt.Sprintf("%v", t.Value)
		if isBasicType(val) {
			return false, "map", basicTypes[val]
		}
		return false, val, "object"
	}
	if k, ok := basicTypes[fmt.Sprint(f.Type)]; ok {
		return false, fmt.Sprint(f.Type), k
	}
	return false, fmt.Sprint(f.Type), "object"
}

func isBasicType(Type string) bool {
	if _, ok := basicTypes[Type]; ok {
		return true
	}
	return false
}

// regexp get json tag
func grepJSONTag(tag string) string {
	r, _ := regexp.Compile(`json:"([^"]*)"`)
	matches := r.FindAllStringSubmatch(tag, -1)
	if len(matches) > 0 {
		return matches[0][1]
	}
	return ""
}

// append models
func appendModels(pkgpath, controllerName string, realTypes []string) {
	for _, realType := range realTypes {
		if realType != "" && !isBasicType(strings.TrimLeft(realType, "[]")) &&
			!strings.HasPrefix(realType, "map") && !strings.HasPrefix(realType, "&") {
			if _, ok := modelsList[pkgpath+controllerName][realType]; ok {
				continue
			}
			_, mod, newRealTypes := getModel(realType)
			modelsList[pkgpath+controllerName][realType] = mod
			appendModels(pkgpath, controllerName, newRealTypes)
		}
	}
}

func urlReplace(src string) string {
	pt := strings.Split(src, "/")
	for i, p := range pt {
		if len(p) > 0 {
			if p[0] == ':' {
				pt[i] = "{" + p[1:] + "}"
			} else if p[0] == '?' && p[1] == ':' {
				pt[i] = "{" + p[2:] + "}"
			}
		}
	}
	return strings.Join(pt, "/")
}

func str2RealType(s string, typ string) interface{} {
	var err error
	var ret interface{}

	switch typ {
	case "int", "int64", "int32", "int16", "int8":
		ret, err = strconv.Atoi(s)
	case "bool":
		ret, err = strconv.ParseBool(s)
	case "float64":
		ret, err = strconv.ParseFloat(s, 64)
	case "float32":
		ret, err = strconv.ParseFloat(s, 32)
	default:
		return s
	}

	if err != nil {
		//logger.Warnf("Invalid default value type '%s': %s", typ, s)
		return s
	}

	return ret
}
