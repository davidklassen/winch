confirm_access and the rollback that keeps winch's access.

A firewall or sshd change can lock winch out of a host. A service step
with confirm_access: true protects against it.

```yaml
# winch.yaml
name: demo
hosts:
  web1.example.com: {}
steps:
  - recipe: ssh
recipes:
  ssh:
    steps:
      - file:
          path: /etc/ssh/sshd_config.d/10-hardening.conf
          content: "PasswordAuthentication no\n"
          validate: sshd -t
        notify: reload
    handlers:
      reload:
        - service:
            name: ssh
            reloaded: true
          confirm_access: true
```

1. The helper keeps the old state of each path that the changed steps
   of the recipe wrote or removed in this run.
2. It starts a 60-second rollback timer in a process of its own, then
   runs the step.
3. winch opens a new SSH connection and runs a command, through sudo -n
   when the login user is not root. It tries twice, 5 seconds apart.
4. When that works, the helper stops the timer and the step succeeds.
5. When both tries fail, the helper puts back the old files at once,
   runs daemon-reload after a unit file, and reloads or restarts the
   unit again. The host fails: "no new SSH connection works: <error>;
   the old files are back". When the session ends first, the helper rolls
   back at the session end; when the helper is gone, the timer does it.

The next run applies the change again. A rollback puts back files only;
it does not undo a change of a user or a group.

Without confirm_access, winch gives the same protection to a step that
changes the login user's authorized_keys, ~/.ssh, home, or groups, or
/etc/pam.d, or /etc/sudoers and /etc/sudoers.d when the login user is
not root. The plan
marks such a step. A step that changes sshd's config while ssh.socket
is active, as on Ubuntu, restarts ssh.socket and gets the same
protection.

A step that stops, disables, masks, or removes the SSH server fails:
"this cuts off winch's access". After the last step of a host that
changed something, winch checks the access once more. When it fails,
the host fails, and nothing rolls back.

The access check connects to the port in the controller's SSH config,
so a change of sshd's Port in one run always rolls back. Move sshd to a
new port in three runs: let sshd listen on the old and the new port;
change the port in the SSH config; remove the old port from sshd.
