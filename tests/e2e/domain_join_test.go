//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

func domainJoinSteps(options labOptions) []harness.Step {
	const stateVariable = "OCEAN_E2E_DOMAIN_STATE"
	const script = "verify_domain_join.py"
	debian := probe("debian-domain-join", options.domain, stateVariable, script, []string{"WORKPLACE-01"},
		[]string{"debian-domain-join.json"}, "--debian-image", options.domainImage)
	steps := []harness.Step{requireFile(debian, options.domainImage, "OCEAN_E2E_DEBIAN_IMAGE")}
	for _, fixture := range []struct{ profile, id string }{
		{"server-core", "WORKPLACE-02"},
		{"windows-11", "WORKPLACE-03"},
	} {
		name := fixture.profile + "-domain-join"
		step := probe(name, options.domain, stateVariable, script, []string{fixture.id},
			[]string{name + ".json"}, "--windows-profile", fixture.profile)
		for _, file := range []string{"media.json", "join.json", "machine.json", "identity.json"} {
			step = requireFile(step, filepath.Join(options.domain, fixture.profile, file), fixture.profile+" "+file)
		}
		steps = append(steps, step)
	}
	runtime := harness.Step{Name: "samba-controller-pair", Cases: []string{"WORKPLACE-04"}, Timeout: 4 * time.Minute,
		Command: []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage}}
	if options.sambaImage == "" {
		runtime.BlockedReason = "Provide OCEAN_E2E_SAMBA_IMAGE with the locally built controller image ID."
	} else if _, err := exec.LookPath("podman"); err != nil {
		runtime.BlockedReason = "Install rootless Podman for the directory runtime probe."
	}
	recovery := harness.Step{Name: "directory-backup-recovery", Cases: []string{"WORKPLACE-07"}, Timeout: 4 * time.Minute,
		Command:       []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage, "--restore"},
		BlockedReason: runtime.BlockedReason}
	if _, err := exec.LookPath("openssl"); err != nil && recovery.BlockedReason == "" {
		recovery.BlockedReason = "Install OpenSSL for the encrypted backup recovery probe."
	}
	pairRecovery := harness.Step{Name: "directory-pair-recovery", Cases: []string{"WORKPLACE-13"}, Timeout: 4 * time.Minute,
		Command:       []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage, "--restore-pair"},
		BlockedReason: recovery.BlockedReason}
	delegation := harness.Step{Name: "directory-machine-authorization", Cases: []string{"WORKPLACE-08"}, Timeout: 2 * time.Minute,
		Command:       []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage, "--delegated-join"},
		BlockedReason: recovery.BlockedReason}
	if options.adcliImage == "" && delegation.BlockedReason == "" {
		delegation.BlockedReason = "Provide OCEAN_E2E_ADCLI_IMAGE with the locally built Debian directory client image ID."
	}
	regionalJoin := harness.Step{Name: "regional-directory-join", Cases: []string{"WORKPLACE-09"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestRegionalDirectoryJoin$", "./internal/controlplane"},
		BlockedReason: delegation.BlockedReason}
	if regionalJoin.BlockedReason == "" {
		switch {
		case os.Getenv("OCEAN_E2E_DIRECTORY_ETCD") == "":
			regionalJoin.BlockedReason = "Provide OCEAN_E2E_DIRECTORY_ETCD with a disposable etcd endpoint."
		default:
			if _, err := exec.LookPath("az"); err != nil {
				regionalJoin.BlockedReason = "Install the pinned Azure CLI 2.93.0 for the regional join probe."
			}
		}
	}
	regionalUsers := harness.Step{Name: "regional-directory-users", Cases: []string{"WORKPLACE-10"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestRegionalDirectoryUsers$", "./internal/controlplane"},
		BlockedReason: regionalJoin.BlockedReason}
	regionalGroups := harness.Step{Name: "regional-directory-groups", Cases: []string{"WORKPLACE-11"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestRegionalDirectoryGroups$", "./internal/controlplane"},
		BlockedReason: regionalJoin.BlockedReason}
	cli := harness.Step{Name: "managed-directory-az", Cases: []string{"WORKPLACE-05"}, Timeout: 2 * time.Minute,
		Command: []string{"env", "OCEAN_E2E_DIRECTORY_CLI=1", "go", "test", "-count=1", "-v",
			"-run", "^TestManagedDirectoryHTTP$", "./internal/identity"}}
	if _, err := exec.LookPath("az"); err != nil {
		cli.BlockedReason = "Install the pinned Azure CLI 2.93.0 for the managed directory contract probe."
	}
	fencing := harness.Step{Name: "managed-directory-fencing", Cases: []string{"WORKPLACE-06"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestManagedDirectoryReservation$", "./internal/controlplane"}}
	if os.Getenv("OCEAN_E2E_DIRECTORY_ETCD") == "" {
		fencing.BlockedReason = "Provide OCEAN_E2E_DIRECTORY_ETCD with a disposable etcd endpoint."
	}
	webRegistration := harness.Step{Name: "regional-web-app-registration", Cases: []string{"WORKPLACE-17"}, Timeout: 4 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestRegionalWebApplicationRegistration$", "./internal/controlplane"},
		BlockedReason: fencing.BlockedReason}
	if webRegistration.BlockedReason == "" {
		webRegistration.BlockedReason = cli.BlockedReason
	}
	webClientPreparation := harness.Step{Name: "keycloak-web-client-preparation", Cases: []string{"WORKPLACE-18"}, Timeout: 2 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakWebClientsLab$", "./internal/identity"}}
	if os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_ORIGIN") == "" || os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_CLIENT") == "" {
		webClientPreparation.BlockedReason = "Provide the HTTPS origin and admin client for a disposable Keycloak lab."
	}
	webClientPreparation = requireFile(webClientPreparation, os.Getenv("OCEAN_E2E_KEYCLOAK_ADMIN_SECRET"), "the private Keycloak admin credential")
	directoryFederation := harness.Step{Name: "keycloak-samba-federation", Cases: []string{"WORKPLACE-19"}, Timeout: 3 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakDirectoryFederationLab$", "./internal/identity"}, BlockedReason: webClientPreparation.BlockedReason}
	federationState := os.Getenv("OCEAN_E2E_SAMBA_FEDERATION_STATE")
	if directoryFederation.BlockedReason == "" && federationState == "" {
		directoryFederation.BlockedReason = "Provide OCEAN_E2E_SAMBA_FEDERATION_STATE with the isolated Samba controller pair configured for LDAPS."
	}
	directoryFederation = requireFile(directoryFederation, filepath.Join(federationState, "directory-id"), "the Samba federation fixture state")
	webAdmission := harness.Step{Name: "managed-web-application-admission", Cases: []string{"WORKPLACE-20"}, Timeout: 3 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakWebAdmissionLab$", "./internal/identity"}, BlockedReason: directoryFederation.BlockedReason}
	if webAdmission.BlockedReason == "" {
		webAdmission.BlockedReason = cli.BlockedReason
	}
	webPolicyPrerequisites := webAdmission.BlockedReason
	for _, program := range []string{"python3", "chromium", "node", "certutil"} {
		if _, err := exec.LookPath(program); err != nil && webAdmission.BlockedReason == "" {
			webAdmission.BlockedReason = "Install " + program + " for the integrated CLI and MFA browser probe."
		}
	}
	webAdmission = requireFile(webAdmission, os.Getenv("SSL_CERT_FILE"), "the Keycloak lab CA in SSL_CERT_FILE")
	kerberosBrowser := harness.Step{Name: "managed-kerberos-firefox", Cases: []string{"WORKPLACE-21"}, Timeout: 3 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakKerberosBrowserLab$", "./internal/identity"}, BlockedReason: webPolicyPrerequisites}
	kerberosState := os.Getenv("OCEAN_E2E_KERBEROS_BROWSER_STATE")
	if kerberosBrowser.BlockedReason == "" && kerberosState == "" {
		kerberosBrowser.BlockedReason = "Provide OCEAN_E2E_KERBEROS_BROWSER_STATE with a disposable Samba service keytab and user ticket cache."
	}
	for _, program := range []string{"firefox-esr", "certutil", "curl"} {
		if _, err := exec.LookPath(program); err != nil && kerberosBrowser.BlockedReason == "" {
			kerberosBrowser.BlockedReason = "Install " + program + " for the Kerberos browser test."
		}
	}
	kerberosBrowser = requireFile(kerberosBrowser, filepath.Join(kerberosState, "service.keytab"), "the disposable HTTP service keytab")
	kerberosBrowser = requireFile(kerberosBrowser, filepath.Join(kerberosState, "employee.ccache"), "the disposable Samba ticket cache")
	webCLIRegression := harness.Step{Name: "managed-web-cli-regression", Cases: []string{"WORKPLACE-22"}, Timeout: 5 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakWebCLIRegressionLab$", "./internal/identity"}, BlockedReason: webPolicyPrerequisites}
	if _, err := exec.LookPath("python3"); err != nil && webCLIRegression.BlockedReason == "" {
		webCLIRegression.BlockedReason = "Install Python 3 for the fresh Azure CLI sign-in probe."
	}
	webCLIRegression = requireFile(webCLIRegression, os.Getenv("SSL_CERT_FILE"), "the Keycloak lab CA in SSL_CERT_FILE")
	webCLIRegression = requireFile(webCLIRegression, filepath.Join(kerberosState, "service.keytab"), "the disposable HTTP service keytab")
	joinedBrowser := harness.Step{Name: "joined-debian-web-kerberos", Cases: []string{"WORKPLACE-23"}, Timeout: 4 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakDebianDomainBrowserLab$", "./internal/identity"}, BlockedReason: webClientPreparation.BlockedReason}
	joinedState := os.Getenv("OCEAN_E2E_JOINED_WEB_STATE")
	if joinedBrowser.BlockedReason == "" {
		switch {
		case options.domain == "" || joinedState == "":
			joinedBrowser.BlockedReason = "Provide the running Debian domain-join lab and OCEAN_E2E_JOINED_WEB_STATE."
		default:
			joinedBrowser.BlockedReason = cli.BlockedReason
		}
	}
	joinedBrowser = requireFile(joinedBrowser, filepath.Join(options.domain, "known-hosts"), "the verified SSH host keys for the lab")
	joinedBrowser = requireFile(joinedBrowser, filepath.Join(joinedState, "service.keytab"), "the lab HTTP service keytab")
	windowsBrowser := harness.Step{Name: "joined-windows-web-kerberos", Cases: []string{"WORKPLACE-24"}, Timeout: 4 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestKeycloakWindowsDomainBrowserLab$", "./internal/identity"}, BlockedReason: joinedBrowser.BlockedReason}
	if windowsBrowser.BlockedReason == "" && os.Getenv("OCEAN_E2E_JOINED_WEB_WINDOWS") != "1" {
		windowsBrowser.BlockedReason = "Prepare the disposable Windows domain desktop and set OCEAN_E2E_JOINED_WEB_WINDOWS=1."
	}
	for _, program := range []string{"genisoimage", "python3", "ssh"} {
		if _, err := exec.LookPath(program); err != nil && windowsBrowser.BlockedReason == "" {
			windowsBrowser.BlockedReason = "Install " + program + " for the Windows browser probe."
		}
	}
	windowsBrowser = requireFile(windowsBrowser, filepath.Join(joinedState, "primary-ssh-port"), "the primary controller's loopback SSH port")
	windowsBrowser = requireFile(windowsBrowser, filepath.Join(joinedState, "oauth.key"), "the lab callback TLS key")
	joinedBrowser = requireFile(joinedBrowser, filepath.Join(joinedState, "guest-ssh-port"), "the joined guest's loopback SSH port")
	promotion := harness.Step{Name: "directory-writer-promotion", Cases: []string{"WORKPLACE-12"}, Timeout: 4 * time.Minute,
		Command:       []string{"bash", filepath.Join("lab", "verify_samba_controller.sh"), options.sambaImage, "--promote-writer"},
		BlockedReason: recovery.BlockedReason}
	windowsState := os.Getenv("OCEAN_E2E_WINDOWS_RECOVERY_STATE")
	windowsArchive := os.Getenv("OCEAN_E2E_WINDOWS_RECOVERY_ARCHIVE")
	windowsRecovery := harness.Step{Name: "regional-windows-directory-recovery", Cases: []string{"WORKPLACE-14"}, Timeout: 13 * time.Minute,
		Command:       []string{"go", "test", "-race", "-tags=e2e", "-timeout=13m", "-count=1", "-v", "-run", "^TestRegionalWindowsDirectoryRecovery$", "./internal/controlplane"},
		BlockedReason: fencing.BlockedReason,
		Evidence: []harness.EvidenceSource{{Name: "regional-windows-recovery.json",
			Path: filepath.Join(windowsState, "evidence", "regional-windows-recovery.json")}}}
	if windowsRecovery.BlockedReason == "" {
		switch {
		case options.sambaImage == "":
			windowsRecovery.BlockedReason = "Provide OCEAN_E2E_SAMBA_IMAGE with a controller image ID loaded on both guests."
		case windowsState == "":
			windowsRecovery.BlockedReason = "Provide OCEAN_E2E_WINDOWS_RECOVERY_STATE with the prepared isolated KVM topology."
		case windowsArchive == "":
			windowsRecovery.BlockedReason = "Provide OCEAN_E2E_WINDOWS_RECOVERY_ARCHIVE with the private independent backup."
		default:
			windowsRecovery.BlockedReason = cli.BlockedReason
		}
	}
	windowsRecovery = requireFile(windowsRecovery, filepath.Join(windowsState, "state.json"), "the isolated recovery lab state")
	windowsRecovery = requireFile(windowsRecovery, windowsArchive, "the independent backup")
	windowsRecovery = requireFile(windowsRecovery, filepath.Join(filepath.Dir(windowsArchive), "metadata.json"), "the independent backup manifest")
	windowsRecovery = requireFile(windowsRecovery, filepath.Join("..", "..", "bin", "ocean-agent"), "the locally built Ocean node agent")
	windowsGraph := harness.Step{Name: "regional-windows-directory-graph", Cases: []string{"WORKPLACE-15"}, Timeout: 13 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-timeout=13m", "-count=1", "-v", "-run",
			"^TestRegionalWindowsDirectoryGraph$", "./internal/controlplane"},
		BlockedReason: windowsRecovery.BlockedReason,
		Evidence: []harness.EvidenceSource{{Name: "regional-windows-graph.json",
			Path: filepath.Join(windowsState, "evidence", "regional-windows-graph.json")}}}
	packagedState := os.Getenv("OCEAN_E2E_PACKAGED_DIRECTORY_STATE")
	packaged := harness.Step{Name: "packaged-directory-provisioning", Cases: []string{"WORKPLACE-16"}, Timeout: 7 * time.Minute,
		Command: []string{"go", "test", "-race", "-tags=e2e", "-timeout=7m", "-count=1", "-v", "-run",
			"^TestPackagedDirectoryProvisioning$", "./internal/controlplane"},
		BlockedReason: fencing.BlockedReason,
		Evidence: []harness.EvidenceSource{{Name: "packaged-directory.json",
			Path: filepath.Join(packagedState, "evidence", "packaged-directory.json")}}}
	if packaged.BlockedReason == "" {
		switch {
		case options.sambaImage == "":
			packaged.BlockedReason = "Provide OCEAN_E2E_SAMBA_IMAGE with a controller image ID loaded on both packaged hosts."
		case packagedState == "":
			packaged.BlockedReason = "Provide OCEAN_E2E_PACKAGED_DIRECTORY_STATE with the prepared three-guest directory lab."
		default:
			packaged.BlockedReason = cli.BlockedReason
		}
	}
	packaged = requireFile(packaged, filepath.Join(packagedState, "state.json"), "the packaged directory KVM lab")
	packaged = requireFile(packaged, options.packageDeb, "OCEAN_E2E_PACKAGE with the installed agent package")
	smbFixture := os.Getenv("OCEAN_E2E_SMB_MEMBER_FIXTURE")
	smb := probe("kerberos-smb-member", options.domain, stateVariable, "verify_smb_member.py", []string{"WORKPLACE-25"},
		[]string{"kerberos-smb-member.json"}, "--fixture", smbFixture)
	if smb.BlockedReason == "" && smbFixture == "" {
		smb.BlockedReason = "Provide OCEAN_E2E_SMB_MEMBER_FIXTURE with the private credentials for the disposable share."
	}
	for _, user := range []string{"smbwriter", "smbreader", "smbdenied"} {
		smb = requireFile(smb, filepath.Join(smbFixture, user), "the disposable credential for "+user)
	}
	smbQuota := probe("kerberos-smb-quota", options.domain, stateVariable, "verify_smb_member.py", []string{"WORKPLACE-26"},
		[]string{"kerberos-smb-quota.json"}, "--fixture", smbFixture, "--rbd-quota")
	smbQuota = requireFile(smbQuota, filepath.Join(smbFixture, "smbwriter"), "the disposable SMB writer credential")
	smbQuota = requireFile(smbQuota, filepath.Join(smbFixture, "rbd-volume-id"), "the encrypted RBD fixture volume ID")
	smbManaged := harness.Step{Name: "managed-smb-cli", Cases: []string{"WORKPLACE-27"}, Timeout: 6 * time.Minute,
		Command:  []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v", "-run", "^TestPackagedSMBWorker$", "./internal/controlplane"},
		Evidence: []harness.EvidenceSource{{Name: "managed-smb-cli.json", Path: filepath.Join(options.domain, "evidence", "managed-smb-cli.json")}}}
	if options.domain == "" || smbFixture == "" || os.Getenv("OCEAN_E2E_SMB_ETCD") == "" || os.Getenv("OCEAN_E2E_SMB_AZ") == "" {
		smbManaged.BlockedReason = "Provide the prepared SMB member lab, a disposable etcd endpoint and the pinned Azure CLI."
	}
	smbManaged = requireFile(smbManaged, filepath.Join(smbFixture, "member-rbd.json"), "the locally verified SMB member identity and native group grants")
	smbRevocation := smbManaged
	smbRevocation.Name, smbRevocation.Cases = "kerberos-smb-live-revocation", []string{"WORKPLACE-31"}
	smbRevocation.Command = []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v", "-run",
		"^TestPackagedSMBLiveRevocation$", "./internal/controlplane"}
	smbRevocation.Evidence = []harness.EvidenceSource{{Name: "kerberos-smb-revocation.json",
		Path: filepath.Join(options.domain, "evidence", "kerberos-smb-revocation.json")}}
	for _, user := range []string{"smbwriter", "smbreader", "smbdenied"} {
		smbRevocation = requireFile(smbRevocation, filepath.Join(smbFixture, user), "the disposable credential for "+user)
	}
	smbWindowsRun := os.Getenv("OCEAN_E2E_SMB_WINDOWS_RUN_ID")
	smbWindows := probe("kerberos-smb-windows", options.domain, stateVariable, "verify_smb_member.py", []string{"WORKPLACE-28"},
		[]string{"kerberos-smb-windows.json"}, "--fixture", smbFixture, "--windows-run-id", smbWindowsRun)
	if smbWindows.BlockedReason == "" && (smbFixture == "" || smbWindowsRun == "") {
		smbWindows.BlockedReason = "Capture a fresh Windows SMB run with a lab nonce and provide the fixture credentials."
	}
	smbWindows = requireFile(smbWindows, filepath.Join(options.domain, "server-core", "guest-serial.log"), "the Windows SMB serial capture")
	smbWindows = requireFile(smbWindows, filepath.Join(options.domain, "server-core", "machine.json"), "the joined Windows Server Core identity record")
	smbWindows = requireFile(smbWindows, filepath.Join(smbFixture, "member-rbd.json"), "the locally verified SMB domain identity")
	failoverProfile := os.Getenv("OCEAN_E2E_SMB_FAILOVER_PROFILE")
	smbFailover := harness.Step{Name: "kerberos-smb-failover", Cases: []string{"WORKPLACE-29"}, Timeout: 7 * time.Minute,
		Command:  []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-timeout=7m", "-v", "-run", "^TestPackagedSMBFailover$", "./internal/controlplane"},
		Evidence: []harness.EvidenceSource{{Name: "kerberos-smb-failover.json", Path: filepath.Join(options.domain, "evidence", "kerberos-smb-failover.json")}}}
	if options.domain == "" || smbFixture == "" || os.Getenv("OCEAN_E2E_SMB_ETCD") == "" || os.Getenv("OCEAN_E2E_SMB_AZ") == "" || failoverProfile == "" {
		smbFailover.BlockedReason = "Provide the prepared two-member SMB lab, its profile, a disposable etcd endpoint and the pinned Azure CLI."
	}
	smbFailover = requireFile(smbFailover, failoverProfile, "the original two-member lab profile")
	for _, file := range []string{"member-rbd.json", "smbwriter", "failover-state-id", "failover-state.key"} {
		smbFailover = requireFile(smbFailover, filepath.Join(smbFixture, file), "the private SMB fixture file "+file)
	}
	archive := os.Getenv("OCEAN_E2E_SMB_ETCD_ARCHIVE")
	smbRestore := harness.Step{Name: "kerberos-smb-restore", Cases: []string{"WORKPLACE-30"}, Timeout: 14 * time.Minute,
		Command:  []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-timeout=13m", "-v", "-run", "^TestPackagedSMBBackupRestore$", "./internal/controlplane"},
		Evidence: []harness.EvidenceSource{{Name: "kerberos-smb-restore.json", Path: filepath.Join(options.domain, "evidence", "kerberos-smb-restore.json")}}}
	if options.domain == "" || smbFixture == "" || archive == "" || os.Getenv("OCEAN_E2E_SMB_AZ") == "" || os.Getenv("OCEAN_E2E_SMB_RESTORE_WINDOWS_READY") == "" {
		smbRestore.BlockedReason = "Provide the two-member SMB lab, pinned etcd and Azure CLI, and a Windows fixture handoff path."
	}
	smbRestore = requireFile(smbRestore, archive, "the pinned etcd 3.6.17 lab release archive")
	for _, file := range []string{"member-rbd.json", "smbwriter", "smbreader", "smbdenied", "failover-state-id", "failover-state.key"} {
		smbRestore = requireFile(smbRestore, filepath.Join(smbFixture, file), "the private SMB fixture file "+file)
	}
	smbRestore = requireFile(smbRestore, filepath.Join(options.domain, "server-core", "machine.json"), "the joined Windows Server Core identity")
	smbRestore = requireFile(smbRestore, filepath.Join(options.domain, "server-core", "guest-serial.log"), "the Windows Kerberos serial capture")
	desktopKerberos := probe("desktop-kerberos-delegation", options.domain, stateVariable, "verify_desktop_kerberos.py",
		[]string{"WORKPLACE-32"}, []string{"desktop-kerberos-delegation.json"})
	desktopAssignments := harness.Step{Name: "regional-desktop-assignments", Cases: []string{"WORKPLACE-33"}, Timeout: 3 * time.Minute,
		Command: []string{"go", "test", "-mod=readonly", "-race", "-tags=e2e", "-count=1", "-v",
			"-run", "^TestRegionalDesktopAssignments$", "./internal/controlplane"},
		BlockedReason: regionalJoin.BlockedReason}
	return append(steps, runtime, cli, fencing, recovery, delegation, regionalJoin, regionalUsers, regionalGroups, promotion, pairRecovery,
		windowsRecovery, windowsGraph, packaged, webRegistration, webClientPreparation, directoryFederation, webAdmission, kerberosBrowser,
		webCLIRegression, joinedBrowser, windowsBrowser, smb, smbQuota, smbManaged, smbWindows, smbFailover, smbRestore, smbRevocation, desktopKerberos,
		desktopAssignments)
}
