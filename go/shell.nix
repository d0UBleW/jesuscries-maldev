with (import <nixpkgs> {});
mkShell {
    shellHook = ''
    export GOOS=windows
    export GOARCH=amd64
    '';
}
