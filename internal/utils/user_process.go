package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// outputWaitDelay limits how long Run waits for the output after the program
// exits. Processes that the program started inherit its output pipes and can
// keep them open long after it exits.
var outputWaitDelay = 5 * time.Second

// UserSession is the session of the user working at the computer.
type UserSession struct {
	ID    uint32
	User  string // DOMAIN\user
	token windows.Token
}

// OpenUserSession opens the session of the user working at the computer, or
// returns ErrNoUserSession. It needs the SeTcbPrivilege, so it works only in
// the service running as LocalSystem.
func OpenUserSession() (*UserSession, error) {
	session, err := findUserSession()
	if err != nil {
		return nil, err
	}
	user := session.qualifiedUser()
	var token windows.Token
	if err := windows.WTSQueryUserToken(session.ID, &token); err != nil {
		return nil, fmt.Errorf("get token of user %s in session %d: %w", user, session.ID, err)
	}
	return &UserSession{ID: session.ID, User: user, token: token}, nil
}

// Close releases the user's token.
func (s *UserSession) Close() error {
	return s.token.Close()
}

// GrantRead lets the user read and execute the file at path. The file can
// stay in a directory that the user cannot open, such as the service's temp
// directory C:\Windows\SystemTemp: Windows lets every user pass through
// directories to a file they have access to.
func (s *UserSession) GrantRead(path string) error {
	user, err := s.token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get user of session %d: %w", s.ID, err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read permissions of %s: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read permissions of %s: %w", path, err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, dacl)
	if err != nil {
		return fmt.Errorf("build permissions of %s: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("set permissions of %s: %w", path, err)
	}
	return nil
}

// Run runs args[0] with the arguments args[1:] as the user and returns its
// exit code. The program runs on the user's desktop without a console window,
// with the user's environment, in the user's profile directory. stdout and
// stderr receive its output; nil discards it and passing the same writer
// combines both streams. When ctx ends, Run terminates the program and
// returns ctx.Err().
func (s *UserSession) Run(ctx context.Context, args []string, stdout, stderr io.Writer) (int, error) {
	return runWithToken(ctx, s.token, args, stdout, stderr)
}

// PowerShellPath returns the full path of Windows PowerShell, so that starting
// it does not depend on PATH or on the current directory.
func PowerShellPath() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		dir = filepath.Join(os.Getenv("SystemRoot"), "System32")
	}
	return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe")
}

func runWithToken(ctx context.Context, token windows.Token, args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return -1, errors.New("no program to run")
	}
	if err := ctx.Err(); err != nil {
		return -1, err
	}

	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return -1, err
	}
	profileDir, err := token.GetUserProfileDirectory()
	if err != nil {
		return -1, fmt.Errorf("get user profile directory: %w", err)
	}
	dir, err := windows.UTF16PtrFromString(profileDir)
	if err != nil {
		return -1, err
	}
	// Without an explicit desktop, the program would get a hidden
	// non-interactive one, and windows it opens would be invisible.
	desktop, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return -1, err
	}

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return -1, fmt.Errorf("create user environment: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	stdio, err := newChildStdio(stdout, stderr)
	if err != nil {
		return -1, err
	}
	defer stdio.close()

	// Let the program inherit its standard handles and nothing else.
	handles := stdio.childHandles()
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return -1, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return -1, err
	}

	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.Desktop = desktop
	si.StdInput = stdio.in
	si.StdOutput = stdio.out
	si.StdErr = stdio.err

	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT)
	err = windows.CreateProcessAsUser(token, nil, cmdLine, nil, nil, true, flags, env, dir, &si.StartupInfo, &pi)
	// The program has its own copies now; ours would keep the pipes open.
	stdio.closeChildHandles()
	if err != nil {
		return -1, fmt.Errorf("start %s: %w", args[0], err)
	}
	windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	copied := stdio.copyOutput()

	exited := make(chan struct{})
	go func() {
		windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		close(exited)
	}()

	killed := false
	select {
	case <-exited:
	case <-ctx.Done():
		killed = windows.TerminateProcess(pi.Process, 1) == nil
		<-exited
	}

	select {
	case <-copied:
	case <-time.After(outputWaitDelay):
		stdio.closeReaders()
		<-copied
	}

	if killed {
		return -1, ctx.Err()
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return -1, fmt.Errorf("get exit code: %w", err)
	}
	return int(code), nil
}

// childStdio holds the standard handles of a child process and the pipes that
// bring its output back to this process.
type childStdio struct {
	in, out, err windows.Handle // handles for the child

	nul     windows.Handle
	writers []*os.File // write ends of the pipes, used by the child
	readers []*os.File // read ends of the pipes
	dests   []io.Writer
}

func newChildStdio(stdout, stderr io.Writer) (*childStdio, error) {
	c := &childStdio{}
	nulName, err := windows.UTF16PtrFromString(os.DevNull)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(sa))
	nul, err := windows.CreateFile(nulName,
		windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		&sa, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	c.nul = nul
	c.in = nul

	if c.out, err = c.output(stdout); err != nil {
		c.close()
		return nil, err
	}
	if stderr != nil && sameWriter(stdout, stderr) {
		c.err = c.out
	} else if c.err, err = c.output(stderr); err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

// output returns the child's handle for an output stream: the write end of a
// pipe whose content goes to w, or NUL if w is nil.
func (c *childStdio) output(w io.Writer) (windows.Handle, error) {
	if w == nil {
		return c.nul, nil
	}
	r, pw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	h := windows.Handle(pw.Fd())
	if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		r.Close()
		pw.Close()
		return 0, err
	}
	c.readers = append(c.readers, r)
	c.writers = append(c.writers, pw)
	c.dests = append(c.dests, w)
	return h, nil
}

// childHandles returns the distinct handles that the child inherits.
func (c *childStdio) childHandles() []windows.Handle {
	var handles []windows.Handle
	for _, h := range []windows.Handle{c.in, c.out, c.err} {
		if !slices.Contains(handles, h) {
			handles = append(handles, h)
		}
	}
	return handles
}

func (c *childStdio) closeChildHandles() {
	for _, w := range c.writers {
		w.Close()
	}
	c.writers = nil
	if c.nul != 0 {
		windows.CloseHandle(c.nul)
		c.nul = 0
	}
}

// copyOutput copies the output of the child to the destinations and closes
// the returned channel when all pipes are closed.
func (c *childStdio) copyOutput() <-chan struct{} {
	done := make(chan struct{})
	remaining := make(chan struct{}, len(c.readers))
	for i := range c.readers {
		go func(r *os.File, w io.Writer) {
			io.Copy(w, r)
			remaining <- struct{}{}
		}(c.readers[i], c.dests[i])
	}
	go func() {
		for range c.readers {
			<-remaining
		}
		close(done)
	}()
	return done
}

// closeReaders closes the read ends of the pipes, which also interrupts
// copying in progress.
func (c *childStdio) closeReaders() {
	for _, r := range c.readers {
		r.Close()
	}
}

func (c *childStdio) close() {
	c.closeChildHandles()
	c.closeReaders()
}

// sameWriter reports whether a and b are the same writer, like os/exec does
// for Stdout and Stderr. Comparing writers of incomparable types panics, so
// such writers are treated as different.
func sameWriter(a, b io.Writer) (same bool) {
	defer func() { _ = recover() }()
	return a == b
}
