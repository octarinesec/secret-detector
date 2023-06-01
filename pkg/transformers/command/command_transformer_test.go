package command

import (
	"github.com/octarinesec/secret-detector/pkg/transformers/tests"
	"testing"
)

var testCases = []tests.TestCase{
	{"command with args", "cat input.txt | grep 'keyword' >> result.txt ; wc -l < result.txt &", map[string]string{"arg2_0": "result.txt", "arg3_0": "wc", "arg4_0": "result.txt", "arg0_0": "cat", "arg0_1": "input.txt", "arg1_0": "grep", "arg1_1": "keyword"}},
	{"command with args", "docker-compose up -d --build | tee log.txt", map[string]string{"arg0_0": "docker-compose", "arg0_1": "up", "arg1_0": "tee", "arg1_1": "log.txt"}},
	{"command with args", "cat input.txt | grep 'example' | sort > output.txt", map[string]string{"arg0_1": "input.txt", "arg1_0": "grep", "arg1_1": "example", "arg2_0": "sort", "arg3_0": "output.txt", "arg0_0": "cat"}},
	{"command with args", "docker-compose up -d --build", map[string]string{"arg0_0": "docker-compose", "arg0_1": "up"}},
	{"command with args", "export MY_VARIABLE=value", map[string]string{"arg0_0": "export", "arg0_1": "MY_VARIABLE=value"}},
	{"command with args", "echo \"MY_VARIABLE=value\" >> .env", map[string]string{"arg0_1": "MY_VARIABLE=value", "arg0_0": "echo", "arg1_0": ".env"}},
	{"command with args", "setx MY_VARIABLE value", map[string]string{"arg0_0": "setx", "arg0_1": "MY_VARIABLE", "arg0_2": "value"}},
	{"command with args", "heroku config:set MY_VARIABLE=value", map[string]string{"arg0_0": "heroku", "arg0_1": "config:set", "arg0_2": "MY_VARIABLE=value"}},

	{"command with args and flags", "cat ~/my_password.txt | docker login --username foo --password-stdin", map[string]string{"arg1_0": "docker", "arg1_1": "login", "username": "foo", "arg0_0": "cat", "arg0_1": "~/my_password.txt"}},
	{"command with args and flags", "kubectl --kubeconfig=\"/Users/g/my= files/kubeconfig\" --context=gke cluster-info", map[string]string{"arg0_0": "kubectl", "kubeconfig": "/Users/g/my= files/kubeconfig", "context": "gke", "arg0_1": "cluster-info"}},
	{"command with args and flags", "kubectl get pods --namespace=default", map[string]string{"arg0_1": "get", "arg0_2": "pods", "namespace": "default", "arg0_0": "kubectl"}},
	{"command with args and flags", "docker run -it --rm ubuntu", map[string]string{"arg0_0": "docker", "arg0_1": "run", "rm": "ubuntu"}},
	{"command with args and flags", "go build -o myapp main.go", map[string]string{"arg0_0": "go", "arg0_1": "build", "o": "myapp", "arg0_2": "main.go"}},
	{"command with args and flags", "git commit -am \"Fix bug\"", map[string]string{"am": "Fix bug", "arg0_0": "git", "arg0_1": "commit"}},
	{"command with args and flags", "aws s3 cp myfile.txt s3://mybucket/ --acl public-read", map[string]string{"arg0_4": "s3://mybucket/", "acl": "public-read", "arg0_0": "aws", "arg0_1": "s3", "arg0_2": "cp", "arg0_3": "myfile.txt"}},
	{"command with args and flags", "npm install --save-dev jest", map[string]string{"save-dev": "jest", "arg0_0": "npm", "arg0_1": "install"}},
	{"command with args and flags", "terraform apply -var-file=myvars.tfvars", map[string]string{"arg0_0": "terraform", "arg0_1": "apply", "var-file": "myvars.tfvars"}},
	{"command with args and flags", "gcc -o myprog myprog.c -lm", map[string]string{"arg0_0": "gcc", "o": "myprog", "arg0_1": "myprog.c"}},
	{"command with args and flags", "docker run -it --rm -v /host:/container ubuntu > output.txt", map[string]string{"arg0_2": "ubuntu", "arg0_0": "docker", "arg0_1": "run", "arg1_0": "output.txt", "v": "/host:/container"}},
}

var commandTransformer = NewTransformer()

func TestTransform(t *testing.T) {
	for _, test := range testCases {
		_, _ = commandTransformer.Transform(test.Input)
	}
	tests.TestTransform(t, commandTransformer, testCases)
}
