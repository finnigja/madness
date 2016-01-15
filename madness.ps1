#######
##
## Alternative Powershell GUI for basic managment of Active Directory accounts.
## Probably won't work straight out of the box, but shouldn't need too much tweaking.
## A little hacky, and probably has bugs, but also pretty simple compared to other options.
##
## Needs a recent-ish version of Powershell (4.0 works for me):
##    PS C:\Users\Administrator> $PSVersionTable.PSVersion
##    Major  Minor  Build  Revision
##    -----  -----  -----  --------
##    4      0      -1     -1
##
## Author: https://twitter.com/chair6
##
## Please don't ask me to write Powershell for you.
##
#######

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

#######
## Global Variables
#######

# AD groups/OUs with required permissions, used by Check-Access function
$script:authorizedGroups = @("NOC Engineer", "Domain Administrator")
$script:authorizedOUs = @("OU=Controlled Users,OU=Accounts,DC=example,DC=com")

# OUs for enabled and disabled accounts
$script:disabledOU = "OU=Disabled Users,DC=example,DC=com"
$script:enabledOU = "CN=Users,DC=example,DC=com"

# SMTP relay that messages will be relayed through (needs to support STARTTLS to protect password)
$script:smtpRelay = "smtp.example.com"
$script:smtpFrom = "IT Support <noreply@example.com>"

# email template: new password message 
$script:msgReset = @"
This message is to inform you of a temporary password that has been set for your account, either during initial account creation or as part of a password reset.

Your temporary password is:
    {0}

Please change this password immediately by [...]. 

Regards,
IT Support
itsupport@example.com
"@

# email template: onboard message
$script:msgOnboard = @"
Your account has been created.

Your username is: {0}

An initial password will be provided via a separate email. [...]"

[insert other user/account onboarding information]

Regards,
IT Support
itsupport@example.com
"@

# working hash table of users being operated against (lookup results are stored in this)
$script:workingUsers = @{}

# list of fields to be included in results table and in detail form for individual account
$script:fieldsTable = @("DN", "First Name", "Last Name", "Username", "Email", "Enabled", "Locked", "Employee Type")
$script:fieldsDetail = @("DN", "Display Name", "First Name", "Last Name", "Username", "Email", "Enabled", "Locked", "Employee ID", "Employee Type", "Groups")

# fieldsConfig is a hash of field names with an array of (numLines, scrollEnabled, textbox, onboardAttr, validator, validationError)
$script:fieldsConfig = [ordered]@{
    "DN" = (1, $False, $Null, $False, $True, "");
    "Display Name" = (1, $False, $Null, $False, $True, "");
    "First Name" = (1, $False, $Null, $True, $True, "");
    "Last Name" = (1, $False, $Null, $True, $True, "");
    "Username" = (1, $False, $Null, $True, $True, "");
    "Email" = (1, $False, $Null, $True, "^(?("")(""[^""]+?""@)|(([0-9a-zA-Z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-zA-Z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,6}))$", "Email address must be valid.");
    "Enabled" = (1, $False, $Null, $False, $True, "");
    "Locked" = (1, $False, $Null, $False, $True, "");
    "Employee ID" = (1, $False, $Null, $True, $True, "Employee ID should be numeric.");  # TBD- add validating expression
    "Employee Type" = (1, $False, $Null, $True, "^((EMP)|(SVC)|(EXT))$", "Employee type should be EMP (employee), EXT (external - eg. contractor), or SVC (service account).");
    "Groups" = (5, $True, $Null, $False, $True, "")
}


# attribute mapping to field label, and boolean indicated inclusion in new user form
$script:attributesToFields = @{
    "distinguishedName" = ("DN", $False);
    "givenName" = ("First Name", $True);
    "sn" = ("Last Name", $True);
    "sAMAccountName" = ("Username", $True);
    "mail" = ("Email", $True);
    "userPrincipalName" = ("Email", $True);
    "uid" = ("Email", $True);
    "memberOf" = ("Groups", $False);
    "enabled" = ("Enabled", $False);
    "lockedOut" = ("Locked", $False);
    "employeeNumber" = ("Employee ID", $True);
    "displayName" = ("Display Name", $True);
    "name" = ("Display Name", $False);
    "employeeType" = ("Employee Type", $True);
}


# buttonConfigs is an ordered hashtable of button labels
$script:buttonConfigs = [ordered]@{
    "Reset and Email" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
    "Unlock Account" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
    "Replicate Account" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
    "Disable Account" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
    "Enable Account" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
    "" = $Null;
    "Onboard and Email" = @{"Enabled"=$False; "Function"=$Null; "Object"=$Null};
}

$script:onboardInProgress = $False

$script:buttonWidth = 150
$script:buttonHeight = 23
$script:buttonBaseX = 620

#######
## Helper Functions
#######

function Check-Access () {
    $groups = Get-ADPrincipalGroupMembership $env:username | Select -ExpandProperty name
    ForEach ($authed_group in $script:authorizedGroups) {
        if ($groups -contains $authed_group) {
            return $True
        }
    }
    $user = Get-ADUser -Identity $env:username
    $ou = $user.DistinguishedName.split(",", 2)[1]
    ForEach ($authed_ou in $script:authorizedOUs) {
        if ($ou -eq $authed_ou) {
            return $True
        }
    }
    $txtStatus.Text = 'ERROR - You do not appear to be in the required group/OU.'
    return $False
 }

function Get-Users ($query="") {
    If ($query.Trim() -eq "") {
        return @{}
    }
    $query = "*" + $query + "*"
    $results = Get-ADUser -Filter {(mail -like $query) -or (sAMAccountName -like $query) -or (displayName -like $query)} -Properties *
    $users = @{}
    ForEach ($result in $results) {
        $user = @{}
        ForEach ($attribute in $script:attributesToFields.Keys) {
            If ($user.Keys -notContains $script:attributesToFields[$attribute][0]) {
                #memberOf attribute is a special case
                If ($attribute -eq 'memberOf') {
                    $result.attribute = ($result.attribute.Keys | Sort) -join "`r`n"
                }
                $user.Add($script:attributesToFields[$attribute][0], $result.$attribute)
            }
        }
        $users.Add($result.DistinguishedName, $user)
    }
    return $users
}

Function Do-UpdateWorkingKey($oldDN, $newDN) {
    if ($newDN -ne $oldDN) {
        $script:workingUsers.Add($newDN, $script:WorkingUsers[$oldDN])
        $script:workingUsers.Remove($oldDN)
     }
}

Function Get-NextUid() {
    $highUid = Get-ADUser -LDAPFilter "(&(objectclass=user)(objectcategory=person))" -Properties uidNumber | Measure-Object -Property uidNumber -Maximum | Select-Object -ExpandProperty Maximum
    return $highUid + 1
}

Function Get-RandomComplexPassword ($length=14, $nonalphanum=2) {
    $Assembly = Add-Type -AssemblyName System.Web
    $password = [System.Web.Security.Membership]::GeneratePassword($length,$nonalphanum)
    return $password
}

function Do-AccountLookup ($strQuery) {
    $script:workingUsers = Get-Users $strQuery
    $objListView.Items.Clear()
    $script:workingUsers.Keys | ForEach-Object {
        $current_user = $_
        $objListviewItem = New-Object System.Windows.Forms.ListViewItem($script:workingUsers.get_Item($current_user).get_Item($script:fieldsTable[0]))
        ForEach ($field in $script:fieldsTable[1..($script:fieldsTable.Length - 1)]) {
            $objListviewItem.SubItems.Add([string]$script:workingUsers.get_Item($current_user).get_Item($field)) | Out-Null
        }
        $objListview.Items.Add($objListviewItem) | Out-Null
    }
}

function Do-AccountLookupUpdate ($currentUser) {
    # instead of requerying all users, we just get the current user
    $tmpUsers = Get-Users $currentUser["Username"]
    $tmpUsers.Keys | ForEach-Object {
        $script:workingUsers[$_] = $tmpUsers[$_]    
    }
    $objListView.Items.Clear()
    # then populate the listbox like in Do-AccountLookup
    $script:workingUsers.Keys | ForEach-Object {
        $current_user = $_
        $objListviewItem = New-Object System.Windows.Forms.ListViewItem($script:workingUsers.get_Item($current_user).get_Item($script:fieldsTable[0]))
        ForEach ($field in $script:fieldsTable[1..($script:fieldsTable.Length - 1)]) {
            $objListviewItem.SubItems.Add([string]$script:workingUsers.get_Item($current_user).get_Item($field)) | Out-Null
        }
        $objListview.Items.Add($objListviewItem) | Out-Null
    }
}


function Do-AccountOnboard ($newUser) {
    $newUser['Display Name'] = $newUser['First Name'] + " " + $newUser['Last Name']

    # validate data in fields
    $validationError = ""
    ForEach ($field in $newUser.Keys) {
        if ($script:fieldsConfig[$field][4] -ne $True) {
            if ($newUser[$field] -notmatch  $script:fieldsConfig[$field][4]) {
                $validationError += "`r`n  - " + $script:fieldsConfig[$field][5]
            }
        }
    }
    if ($validationError -ne "") {
        return Show-Error("Could not create account:" + $validationError)
    }

    $attrs = @{}
    ForEach ($adAttr in $script:attributesToFields.Keys) {
        if ($script:attributesToFields[$adAttr][1]) {
            $attrs.Add($adAttr, $newUser[$script:attributesToFields[$adAttr][0]])
        }
    }
    $attrs['homeDirectory'] = "/home/" + $attrs['sAMAccountName']
    $attrs['uidNumber'] = Get-NextUid
    if ($attrs['uidNumber'] -eq 1) {
        return Show-Error("Could not connect to LDAP service to get new UID, please try again or investigate underlying cause.")
    }
    $attrs['msSFU30NisDomain'] = 'hpcloud'
    $attrs['loginShell'] = "/bin/bash"
    $attrs['unixHomeDirectory'] = "/home/" + $attrs['sAMAccountName']
    $attrs['gidNumber'] = 1000

    # create new account and set attributes
    try {
        $user = New-ADUser -name $newUser['Display Name'] -samaccountname $newUser['Username'] -PassThru
        Set-ADUser -Identity $user -Replace $attrs
    } Catch {
        return Show-Error("Could not create new user.`r`n`r`n{0}." -f $(Error[0]))
    }
    $smtpTo = "{0} <{1}>" -f $newUser["Display Name"], $newUser["Email"]
    Try {
        Send-MailMessage -smtpserver $script:smtpRelay -to $smtpTo -from $script:smtpFrom -subject "Account Onboarding" -body $($script:msgOnboard -f $newUser["Username"]) -useSSL -ErrorAction Stop
    } Catch {
        return Show-Error("Could not send email.`r`n`r`n{0}." -f $($Error[0]))
    }

    Do-AccountLookup($user.sAMAccountName)
    return $True
}

function Do-ResetAndEmail ($currentUser) {
    # <hackjob> occasionally the generated password does not meet complexity requirement, so we iterate multiple attempts if need be
    $success = $False
    For ($attempt = 0; $attempt -le 10; $attempt++) {
        Try {
            $newpwd = Get-RandomComplexPassword
            Set-ADAccountPassword -Identity $currentUser."Username" -NewPassword (ConvertTo-SecureString -AsPlainText $newpwd -Force) -Reset -PassThru
            $success = $True
        } Catch {

        }
        If ($success) { break; }
    }
    if (-Not $success) {
        return Show-Error("Could not reset password, please try again or investigate underlying cause.")
    }
    # </hackjob>
    Set-ADuser -Identity $currentUser."Username" -ChangePasswordAtLogon $True
    Do-DomainReplication($currentUser."DN")
    # we could drop the password onto the clipboard too, if we wanted..
    # [Windows.Forms.Clipboard]::SetText($script:msgReset -f $newpwd)
    # .. or just print it and skip emailing, and communicate it some other way.
    $smtpTo = "{0} <{1}>" -f $currentUser."Display Name", $currentUser."Email"
    Try {
        Send-MailMessage -smtpserver $script:smtpRelay -to $smtpTo -from $script:smtpFrom -subject "Cloud SSO Account Password Reset" -body $($script:msgReset -f $newpwd) -useSSL -ErrorAction Stop
    } Catch {
        return Show-Error("Could not send email.`r`n`r`n{0}." -f $($Error[0]))
    }
    Remove-Variable newpwd
    return $True
}

function Do-DomainReplication ($strDN) {
    #2012 has Sync-ADObject but we're still on 2008 R2 so do it this way
    Start-Job -ScriptBlock {Invoke-Expression ("& repadmin.exe /replsingleobj destdc1.example.com sourcedc.example.com '{0}'" -f $strDN)}
	Start-Job -ScriptBlock {Invoke-Expression ("& repadmin.exe /replsingleobj destdc2.example.com sourcedc.example.com '{0}'" -f $strDN)}
}

#######
## GUI Event Handlers
#######

# handlers for static buttons

[System.EventHandler] $hndlrDoAccountLookup = {
    $objListview.Items.Clear()
    $txtStatus.Text = "Executing account lookup..."
    $query = $txtQuery.Text
    Do-AccountLookup($query)
    If ($script:workingUsers.Count -eq 0) {
        $txtStatus.Text = "Lookup completed, no accounts located."
    }
    Else{
        $txtStatus.Text = "Lookup completed, {0} accounts located." -f $script:workingUsers.Count
    }
}

[System.EventHandler] $hndlrDoAccountCreate = {
    if (Check-Access) {
        $script:onboardInProgress = $True
        $script:buttonConfigs."Onboard and Email".Object.Enabled = $True
        Do-ToggleOnboardFields
    }
}

# handlers for buttons defined out of $script:buttonConfigs

[System.EventHandler] $script:buttonConfigs."Reset and Email".Function = {
    if (Check-Access) {
        $currentUser = Get-CurrentUser
        if (Confirm-Action ("Reset password for {0} and email to {1}?" -f $currentUser."Display Name", $currentUser."Email")) {
            if (Do-ResetAndEmail($currentUser)) {
               $txtStatus.Text = "Password reset for {0} completed, replicated, and emailed to {1}." -f $currentUser."Display Name", $currentUser."Email"
            } else {
                $txtStatus.Text = "Action failed."
            }
        }
    }
}

[System.EventHandler] $script:buttonConfigs."Unlock Account".Function = {
    If (Check-Access) {
        $currentUser = Get-CurrentUser
        if (Confirm-Action ("Unlock account for {0}?" -f $currentUser."Display Name")) {
            Get-ADUser -Identity $currentUser."Username" | Unlock-ADAccount
            $script:buttonConfigs."Unlock Account".Enabled = $False
            Do-DomainReplication($currentUser."DN")
            Do-AccountLookup($currentUser)
            Do-RenderUserDetail($currentUser)
            $objListView.Focus()
            $objListView.Items[$currentUser.Index].Selected = $True
            $txtStatus.Text = "Account unlock for " + $currentUser."Display Name" + " completed." 
        }
    }
}

[System.EventHandler] $script:buttonConfigs."Enable Account".Function = {
    If (Check-Access) {
        $currentUser = Get-CurrentUser
        if (Confirm-Action ("Enable account for {0} ({1})?." -f $currentUser."Display Name", $currentUser."Email")) {
            $user = Get-ADUser -Identity $currentUser."Username"
            $oldDN = $currentUser.DN
            Enable-ADAccount $user
            $user = Move-ADObject $user -TargetPath $script:enabledOU -PassThru
            $newDN = $user.DistinguishedName
            $currentUser.DN = $newDN
            Do-UpdateWorkingKey $oldDN $newDN
            $script:buttonConfigs."Enable Account".Enabled = $False
            Do-DomainReplication($currentUser."DN")
            Do-AccountLookupUpdate($currentUser)
            Do-RenderUserDetail($currentUser)
            $objListView.Focus()
            $objListView.Items[$currentUser.Index].Selected = $True
            $txtStatus.Text = "Account enable for " + $currentUser."Display Name" + " completed." 
        }
    }
}

[System.EventHandler] $script:buttonConfigs."Disable Account".Function = {
    if (Check-Access) {
        $currentUser = Get-CurrentUser
        if (Confirm-Action ("Disable account for {0} ({1})?." -f $currentUser."Display Name", $currentUser."Email")) {
            $user = Get-ADUser -Identity $currentUser."Username"
            $oldDN = $currentUser.DN
            Disable-ADAccount $user
            $user = Move-ADObject $user -TargetPath $script:disabledOU -PassThru
            $newDN = $user.DistinguishedName
            $currentUser.DN = $newDN
            Do-UpdateWorkingKey $oldDN $newDN
            Do-AccountLookupUpdate($currentUser)
            Do-RenderUserDetail($currentUser)
            $objListView.Focus()
            $objListView.Items[$currentUser."Index"].Selected = $True
            $txtStatus.Text = "Account disabled for {0} ({1})." -f $currentUser."Display Name", $currentUser."Email"
        }
    }
}

[System.EventHandler] $script:buttonConfigs."Replicate Account".Function = {
    if (Check-Access) {
        $currentUser = Get-CurrentUser
        if (Confirm-Action ("Perform domain replication for {0} ({1})?" -f $currentUser."Display Name", $currentUser."Email")) {
            Do-DomainReplication($currentUser."DN")
            $txtStatus.Text = "Account replication for {0} ({1}) triggered." -f $currentUser."Display Name", $currentUser."Email"
        }
    }
}

[System.EventHandler] $script:buttonConfigs."Onboard and Email".Function = {
    if (Check-Access) {
        $newUser = @{};
        $newUserText = "";
        $script:fieldsConfig.Keys | ForEach-Object {
            if ($script:fieldsConfig.Get_Item($_)[3]) {
                $newUser.Set_Item($_, $script:fieldsConfig.Get_Item($_)[2].Text)
                $newUserText += "`r`n{0}: {1}" -f $_, $newUser.Get_Item($_)
            }
        }
        if (Confirm-Action ("Onboard account?`r`n{0}" -f $newUserText)) {
            if (Do-AccountOnboard($newUser)) {
                $script:buttonConfigs."Onboard and Email".Object.Enabled = $False
                $script:onboardInProgress = $False
                 Do-ToggleOnboardFields -submitted $True
                $txtStatus.Text = "Account onboard for {0} completed, email sent to {1}." -f $newUser."Display Name", $newUser."Email"
            }
        }
    }
}

#######
## GUI Helpers
#######

function Confirm-Action ($strPrompt) {
    $result = [System.Windows.Forms.MessageBox]::Show($strPrompt , "Confirm Action" , [System.Windows.Forms.MessageBoxButtons]::YesNo)
    if ($result -eq "YES") {
        return $True
    }
    $txtStatus.Text = "Action cancelled."
    return $False  
}

function Show-Error($strError) {
    [System.Windows.Forms.MessageBox]::Show($strError , "Error", [System.Windows.Forms.MessageBoxButtons]::OK) | Out-Null
    return $False
}

function Get-CurrentUser () {
    $currentUser = $Null
    $currentIdx = $objListView.SelectedIndices[0]
    if ($currentIdx -ne $Null) {
        $currentUser = @{}
        $currentDN = $objListView.SelectedItems[0].Text
        $currentUser.Add("Index", $currentIdx)
        ForEach ($attr in $script:fieldsConfig.Keys) {
            $currentUser.Add($attr, $script:workingUsers.$currentDN.$attr)
        }
    }
    return $currentUser
}

Function Do-RenderUserDetail($currentUser=$Null) {
    $script:onboardInProgress = $False
    if ($currentUser -eq $Null) {
        $currentUser = Get-CurrentUser
    }
    if ($currentUser -ne $Null) {
        $dn = $currentUser.DN
        foreach ($key in $script:fieldsDetail) {
            $script:fieldsConfig.Get_Item($key)[2].Text = $script:workingUsers.get_Item($dn).get_Item($key)
            $script:fieldsConfig.Get_Item($key)[2].ReadOnly = $True
        }

        $script:buttonConfigs."Reset and Email".Object.Enabled = $True
        $script:buttonConfigs."Replicate Account".Object.Enabled = $True
        if ($script:workingUsers.get_Item($dn).get_Item('Locked') -eq $True) {
            $script:buttonConfigs."Unlock Account".Object.Enabled = $True
        } else {
            $script:buttonConfigs."Unlock Account".Object.Enabled = $False
        }
        if ($script:workingUsers.get_Item($dn).get_Item('Enabled') -eq $False) {
            $script:buttonConfigs."Enable Account".Object.Enabled = $True
            $script:buttonConfigs."Disable Account".Object.Enabled = $False
        } else {
            $script:buttonConfigs."Enable Account".Object.Enabled = $False
            $script:buttonConfigs."Disable Account".Object.Enabled = $True
        }
    }
    else {
        foreach ($key in $script:fieldsDetail) {
            $script:fieldsConfig.Get_Item($key)[2].Text = ""
        }
        $script:buttonConfigs."Reset and Email".Object.Enabled = $False
        $script:buttonConfigs."Replicate Account".Object.Enabled = $False
        $script:buttonConfigs."Disable Account".Object.Enabled = $False
    }
}

function Do-ToggleOnboardFields ($submitted=$False) {
    if ($script:onboardInProgress) {
        $script:fieldsConfig.Keys | ForEach-Object {
            $script:fieldsConfig.Get_Item($_)[2].Text = ""
            if ($script:fieldsConfig.Get_Item($_)[3]) {
                $script:fieldsConfig.Get_Item($_)[2].ReadOnly = $False
            }
        }
    } else {
        if ($submitted -eq $False) {
            if (Confirm-Action ("Cancel account creation and erase data entered?") -eq $False) {
                return
            }
        }
        $script:onboardInProgress = $False
        $script:fieldsConfig.Keys | ForEach-Object {
            $script:fieldsConfig.Get_Item($_)[2].ReadOnly = $True
            $script:fieldsConfig.Get_Item($_)[2].Text = ""
        }
    }
}

function Sort-ListView {
    # from https://etechgoodness.wordpress.com/2014/02/25/sort-a-windows-forms-listview-in-powershell-without-a-custom-comparer/
    param([parameter(Position=0)][UInt32]$Column)
    $Numeric = $true # determine how to sort
    if($Script:LastColumnClicked -eq $Column){
        $Script:LastColumnAscending = -not $Script:LastColumnAscending
    }
    else {
        $Script:LastColumnAscending = $true
    }
    $Script:LastColumnClicked = $Column
    $ListItems = @(@(@())) # three-dimensional array; column 1 indexes the other columns, column 2 is the value to be sorted on, and column 3 is the System.Windows.Forms.ListViewItem object
 
    foreach($ListItem in $objListView.Items) {
            # if all items are numeric, can use a numeric sort
        if($Numeric -ne $false) {
            try {
                $Test = [Double]$ListItem.SubItems.Text[$Column]
            } catch {
                $Numeric = $false # a non-numeric item was found, so sort will occur as a string
            }
        }
        $ListItems += ,@($ListItem.SubItems.Text[$Column], $ListItem)
    }
 
    $EvalExpression = {
        if($Numeric)
        {       return [Double]$_[0] }
        else
        {       return [String]$_[0] }
    }
 
    $ListItems = $ListItems | Sort-Object -Property @{Expression=$EvalExpression; Ascending=$Script:LastColumnAscending}
 
    $objListView.BeginUpdate()
    $objListView.Items.Clear()
    foreach($ListItem in $ListItems) {
        $objListView.Items.Add($ListItem[1])
    }
    $objListView.EndUpdate()
}

#######
## GUI Initialization
#######
 
$frmUI = New-Object System.Windows.Forms.Form
$frmUI.Text = "User Account Managment"
$frmUI.Size = New-Object System.Drawing.Size(800,600)
$frmUI.StartPosition = "CenterScreen"
$frmUI.KeyPreview = $True
$frmUI.MaximumSize = $frmUI.Size
$frmUI.MinimumSize = $frmUI.Size

# first row - lookup input / button 
$lblQuery = New-Object System.Windows.Forms.Label
$lblQuery.Location = New-Object System.Drawing.Size(5,5)
$lblQuery.Size = New-Object System.Drawing.Size(140,20)
$lblQuery.Text = "Email / Username / Name:"
$frmUI.Controls.Add($lblQuery)

$txtQuery = New-Object System.Windows.Forms.TextBox
$txtQuery.Location = New-Object System.Drawing.Size(145,5)
$txtQuery.Size = New-Object System.Drawing.Size(270,20)
$frmUI.Controls.Add($txtQuery)

$btnLookup = New-Object System.Windows.Forms.Button
$btnLookup.Location = New-Object System.Drawing.Size(($buttonBaseX - $buttonWidth - 40),5)
$btnLookup.Size = New-Object System.Drawing.Size($buttonWidth,$buttonHeight)
$btnLookup.Text = "Lookup"
$btnLookup.Add_Click($hndlrDoAccountLookup)
$frmUI.Controls.Add($btnLookup)

$btnCreateAccount = New-Object System.Windows.Forms.Button
$btnCreateAccount.Location = New-Object System.Drawing.Size($buttonBaseX,5)
$btnCreateAccount.Size = New-Object System.Drawing.Size($buttonWidth,$buttonHeight)
$btnCreateAccount.Text = "Create Account"
$btnCreateAccount.Add_Click($hndlrDoAccountCreate)
$frmUI.Controls.Add($btnCreateAccount)

# second row - lookup results
$lblResult = New-Object System.Windows.Forms.Label
$lblResult.Location = New-Object System.Drawing.Size(5,45)
$lblResult.Size = New-Object System.Drawing.Size(400,15)
$lblResult.Text = "Lookup Results"
$frmUI.Controls.Add($lblResult)

$objListview = New-Object System.Windows.Forms.Listview
$objListview.Location = New-Object System.Drawing.Size(5,60) 
$objListview.Size = New-Object System.Drawing.Size(780,140)
$objListview.Height = 140
$objListview.View = [System.Windows.Forms.View]::Details
$objListView.MultiSelect = $False
$objListView.FullRowSelect = $True
foreach ($field in $script:fieldsTable) {
    $col = $objListview.Columns.Add($field)
    $col.Width = 120
}
$objListView.add_ColumnClick({Sort-ListView $_.Column})
$frmUI.Controls.Add($objListview) 
$objListview.Add_SelectedIndexChanged({Do-RenderUserDetail})

# third row - individual account details
$lblAccount = New-Object System.Windows.Forms.Label
$lblAccount.Location = New-Object System.Drawing.Size(5,210)
$lblAccount.Size = New-Object System.Drawing.Size(400,15)
$lblAccount.Text = "Account Details"
$frmUI.Controls.Add($lblAccount)

$details_baseheight = 230
$details_rowheight = 25
$details_rowwidth = 480

# build out the text fields to hold the account details
$i = 0
ForEach ($fieldName in $script:fieldsDetail) {

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Size(5, ($details_baseheight + ($details_rowheight*$i)))
    $lbl.Size = New-Object System.Drawing.Size(100,$details_rowheight)
    $lbl.Text = $fieldName + ":"
    $frmUI.Controls.Add($lbl)
    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Location = New-Object System.Drawing.Size(105, ($details_baseheight + ($details_rowheight*$i)))
    $rows = $script:fieldsConfig.Get_Item($fieldName)[0]
    $scrollable = $script:fieldsConfig.Get_Item($fieldName)[1]
    $txt.Size = New-Object System.Drawing.Size($details_rowwidth, (15*$rows))
    $txt.ReadOnly = $True
    if ($rows -gt 1) {
        $txt.MultiLine = $True
    }
    if ($scrollable) {
        $txt.ScrollBars = "Vertical"
    }
    $script:fieldsConfig.Get_Item($fieldName)[2] = $txt
    $frmUI.Controls.Add($txt)
    $i += 1
}


# build out the buttons
$i = 0
ForEach ($buttonLabel in $script:buttonConfigs.Keys) {
    if ($buttonLabel -ne "") {
        $script:buttonConfigs.$buttonLabel.Object = New-Object System.Windows.Forms.Button
        $script:buttonConfigs.$buttonLabel.Object.Location = New-Object System.Drawing.Size($buttonBaseX, ($details_baseheight + ($details_rowheight*$i)))
        $script:buttonConfigs.$buttonLabel.Object.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $script:buttonConfigs.$buttonLabel.Object.Text = $buttonLabel
        $script:buttonConfigs.$buttonLabel.Object.Add_Click($script:buttonConfigs.$buttonLabel.Function)
        $script:buttonConfigs.$buttonLabel.Object.Enabled = $script:buttonConfigs.$buttonLabel.Enabled
        $frmUI.Controls.Add($script:buttonConfigs.$buttonLabel.Object)
    }
    $i += 1
}

# misc gui stuff

$txtStatus = New-Object System.Windows.Forms.StatusBar
$txtStatus.Text = "Ready..."
$frmUI.Controls.Add($txtStatus)
 
$frmUI.Add_KeyDown({if ($_.KeyCode -eq "Enter") {$hndlrDoAccountLookup.Invoke($Null, [EventArgs]::Empty)}})
$frmUI.Add_KeyDown({if ($_.KeyCode -eq "Escape") {$frmUI.Close()}})

$frmUI.Add_Shown({$frmUI.Activate()})
$icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")
$frmUI.Icon = $icon
Check-Access | Out-Null
[void] $frmUI.ShowDialog()

