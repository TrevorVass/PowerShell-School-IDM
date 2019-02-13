# ---------- FUNCTIONS ----------

# Creates a random password suitable for use with AD's default password policy.
# Outputs a SecureString.
function Create-ADPassword {
    # Define the type of characters we'll use in the password.
    $lowerCaseCharacters = 'abcdefghiklmnoprstuvwxyz'
    $upperCaseCharacters = 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $numberCharacters = '1234567890'
    $specialCharacters = '!"§$%&/()=?}][{@#*+'

    $password = ""
    1..5 | ForEach-Object {
        $random = Get-Random -Maximum $lowerCaseCharacters.length
        $password += [string]$lowerCaseCharacters[$random]
    }

    $random = Get-Random -Maximum $upperCaseCharacters.length
    $password += [string]$upperCaseCharacters[$random]

    $random = Get-Random -Maximum $numberCharacters.length
    $password += [string]$numberCharacters[$random]

    $random = Get-Random -Maximum $specialCharacters.length
    $password += [string]$specialCharacters[$random]

    return ConvertTo-SecureString $password -AsPlainText -Force
}

# Create an account name from a supplied first name and last name.
# Checks the System of Record to determine if an account name collides with an existing one,
# iterates the account name until no collision exists.
# If the System of Record is not available, the account name will
# be returned without a check for collision.
# Return an empty string if neither are provided.
function Create-AccountName {
    param (
        $firstName,
        $lastName,
        $sor
    )
    # The account name we'll create.
    $accoutName = ''

    # Remove any special characters in the names.
    $firstName = $firstName -replace '[^a-zA-Z0-9]', ''
    $lastName = $lastName -replace '[^a-zA-Z0-9]', ''

    if ($firstName -ne "") {
        # A first name was provided.
        if ($lastName -ne "") {
            # A last name was provided.
            $firstLetter = $firstName[0]
            $accountName = "$firstLetter$lastName".ToLower()
        } else {
            # A last name was not provided.
            $accountName = $firstName.ToLower()
        }
    } else {
        # A first name was not provided.
        if ($lastName -ne "") {
            # A last name was provided.
            $accountName = $lastName.ToLower()
        } else {
            # Neither a first name or last name were provided.
            return ""
        }
    }

    # Check whether there is a collision in the System of Record.
    if ($sor -ne $null) {
        $existingAccountName = $sor | Where-Object { ($_.AccountName -eq $accountName) }
        $index = 0
        while ($existingAccountName -ne $null) {
            $newAccountName = "{0}{1}" -f $accountName,++$index
            $existingAccountName = $sor | Where-Object { ($_.AccountName -eq $newAccountName) }
        }
        # Add a number to the account name to prevent a collision if one is found.
        if ($index -gt 0) {
            $accountName = "{0}{1}" -f $accountName,$index
        }
    }

    # Return the unique account name
    return $accountName
}

# Returns the next available account ID.
function Get-NextAccountID {
    $accountID = Get-Content .\NextAccountID.txt
    $nextAccountID = [int64]$accountID + 1
    Set-Content .\NextAccountID.txt $nextAccountID
    return [int64]$accountID
}

# Sets the user's group membership in Active Directory based upon their
# properties within the System of Record.
function Set-ADGroupMembership {
    param (
        $account
    )
    if ($account -ne $null) {
        # Clear any current group membership. (Retain Domain Users.)
        $groupsToRemove = Get-ADPrincipalGroupMembership $account.AccountName | Where-Object { ($_.SamAccountName -ne "Domain Users") }
        $groupsToRemove | ForEach-Object {
            Remove-ADGroupMember $_ -Members $account.AccountName -Confirm:$false
        }

        # Add the user to groups based upon their account type, department, office, and job title.
        if ($account.AccountType -eq "Employee") {
            # The user is an employee or teacher.
            switch ($account.Office) {
                "District Office" {
                    Add-ADPrincipalGroupMembership $account.AccountName district-staff

                    switch ($account.Department) {
                        "Administration" {
                            Add-ADPrincipalGroupMembership $account.AccountName district-administrators
                            
                            # In this demo, Assistant Superintendents oversee School Administrators
                            # and should have access to their resources.
                            if ($account.JobTitle -eq "Assistant Superintendent") {
                                Add-ADPrincipalGroupMembership $account.AccountName school-administrators
                            }
                        }
                        "IT" {
                            Add-ADPrincipalGroupMembership $account.AccountName it

                            if ($account.JobTitle -eq "Director of Technology") {
                                Add-ADPrincipalGroupMembership $account.AccountName it-managers
                            }

                            # All Engineers need access to their resources.
                            if ($account.JobTitle -like "*Engineer") {
                                Add-ADPrincipalGroupMembership $account.AccountName it-engineers
                            }

                            # All Technicians need access to their resources.
                            if (($account.JobTitle -like "*Technician") -or ($account.JobTitle -eq "Technician")) {
                                Add-ADPrincipalGroupMembership $account.AccountName it-technicians
                            }

                            # All Developers need access to their resources.
                            if (($account.JobTitle -like "*Developer") -or ($account.JobTitle -eq "Developer")) {
                                Add-ADPrincipalGroupMembership $account.AccountName it-developers
                            }
                        }
                    }
                    break
                }
                "Archer Elementary" {
                    switch ($account.Department) {
                        "Administration" {
                            Add-ADPrincipalGroupMembership $account.AccountName archer-administrators,school-administrators
                        }
                        "Education" {
                            Add-ADPrincipalGroupMembership $account.AccountName archer-teachers,teachers
                        }
                        "IT" {
                            Add-ADPrincipalGroupMembership $account.AccountName archer-staff,it
                            
                            # Technicians need access to their resources.
                            if ($account.JobTitle -eq "Technician") {
                                Add-ADPrincipalGroupMembership $account.AccountName it-technicians
                            }
                        }
                    }
                    break
                }
                "Erikson Middle" {
                    switch ($account.Department) {
                        "Administration" {
                            Add-ADPrincipalGroupMembership $account.AccountName erikson-administrators,school-administrators
                        }
                        "Education" {
                            Add-ADPrincipalGroupMembership $account.AccountName erikson-teachers,teachers
                        }
                        "IT" {
                            Add-ADPrincipalGroupMembership $account.AccountName erikson-staff,it

                            # Technicians need access to their resources.
                            if ($account.JobTitle -eq "Technician") {
                                Add-ADPrincipalGroupMembership $account.AccountName it-technicians
                            }
                        }
                    }
                    break
                }
                "Cochran High" {
                    switch ($account.Department) {
                        "Administration" {
                            Add-ADPrincipalGroupMembership $account.AccountName cochran-administrators,school-administrators
                        }
                        "Education" {
                            Add-ADPrincipalGroupMembership $account.AccountName cochran-teachers,teachers
                        }
                        "IT" {
                            Add-ADPrincipalGroupMembership $account.AccountName cochran-staff,it

                            # Technicians need access to their resources.
                            if ($account.JobTitle -eq "Technician") {
                                Add-ADPrincipalGroupMembership $account.AccountName it-technicians
                            }
                        }
                    }
                    break
                }
            }
        } else {
            # The user is a student.
            Add-ADPrincipalGroupMembership $account.AccountName students
            
            switch ($account.Office) {
                "Archer Elementary" {
                    Add-ADPrincipalGroupMembership $account.AccountName archer-students
                    break
                }
                "Erikson Middle" {
                    Add-ADPrincipalGroupMembership $account.AccountName erikson-students
                    break
                }
                "Cochran High" {
                    Add-ADPrincipalGroupMembership $account.AccountName cochran-students
                    break
                }
            }
        }
    }
}

# Creates a new account in Active Directory.
# Uses a minimum of properties from the supplied System of Record entry to create the account.
# Call Set-IdmADAccount after creation to fully populate properties and group membership.
function New-IdmADAccount {
    param (
        $account
    )
    if ($account -ne $null) {
        $securePassword = Create-ADPassword
        $fullName = "{0} {1}" -f $account.FirstName,$account.LastName
        $accountName = $account.AccountName
        $fullAccountName = "{0}@scoe.info" -f $account.AccountName

        # Create the user's account in AD.
        # (Supply a limited number of properties.)
        $adAccount = New-ADUser `
            -Name $fullName `
            -DisplayName $fullName `
            -GivenName $account.FirstName `
            -Surname $account.LastName `
            -SAMAccountName $accountName `
            -UserPrincipalName $fullAccountName `
            -EmployeeNumber $account.AccountID `
            -Description "Newly created account." `
            -AccountPassword $securePassword `
            -ChangePasswordAtLogon $true `
            -Enabled $true `
            -Path "OU=IDM,DC=scoe,DC=info" `
            -PassThru

        if ($adAccount -ne $null) {
            Write-Output ("`tAD account created: {0}" -f $adAccount.UserPrincipalName)
        } else {
            Write-Output "`tAD account creation failed!"
        }
    } else {
        Write-Output "`tInvalid parameter supplied. Can't create AD account."
    }
}

# Updates an account in Active Directory to reflect the information in the System of Record.
# Uses the properties from the System of Record, and the list of offices (from Office.csv)
# Looks up account information with the supplied Account ID.
function Set-IdmADAccount {
    param (
        $accountID,
        $sor,
        $offices
    )
    # Lookup the account in the System of Record.
    $account = $null
    if ($sor -ne $null) {
        $account = $sor | Where-Object { ($_.AccountID -eq $accountID) }

        if (($account -ne $null) -and ($offices -ne $null)) {
            # The account was found, and the office values provided.

            # Get the account's office details.
            $office = $offices | Where-Object { ($_.Name -eq $account.Office) }
            $officeName = ''
            $streetAddress = ''
            $city = ''
            $state = ''
            $postalCode = ''
            $country = ''
            if ($office -ne $null) {
                $officeName = $office.Name
                $streetAddress = $office.address
                $city = $office.City
                $state = $office.State
                $postalCode = $office.PostalCode
                $country = $office.Country
            }

            # Get the employee's manager
            $managerAccountName = ''
            if ($account.ManagerID -ne '') {
                $manager = $sor | Where-Object { ($_.EmployeeID -eq $account.ManagerID) }
                if ($manager -ne $null) {
                    $managerAccountName = $manager.AccountName
                } else {
                    $managerAccountName = ''
                }
            }

            # Find the user's account in AD.
            $fullName = "{0} {1}" -f $account.FirstName,$account.LastName
            $existingAccountName = $account.AccountName
            
            $accountID = $account.AccountID
            $adAccount = Get-ADUser -Filter { EmployeeNumber -eq $accountID }

            # Determine whether an account rename is required.
            $accountName = $existingAccountName
            $fullAccountName = "{0}@scoe.info" -f $existingAccountName
            if ($adAccount.Name -ne $fullName) {
                # Account needs to be renamed.
                $adAccount = Rename-ADObject $adAccount.ObjectGUID -NewName $fullName -PassThru
                $accountName = Create-AccountName $_.FirstName $_.LastName $sor
                $fullAccountName = "{0}@scoe.info" -f $accountName
                $account.AccountName = $accountName
                $account.Email = $fullAccountName
            }

            if ($adAccount -ne $null) {
                # Update the user's account in AD.

                # Turn empty values into nulls.
                # This tells Set-ADUser below to ignore these values when updating
                # the account.
                $firstName = $null
                if ($account.FirstName -ne '') {
                    $firstName = $account.FirstName
                }
                $lastName = $null
                if ($account.LastName -ne '') {
                    $lastName = $account.LastName
                }
                $phone = $null
                if ($account.Phone -ne '') {
                    $phone = $account.Phone
                }
                $employeeID = $null
                if ($account.EmployeeID -ne '') {
                    $employeeID = $account.EmployeeID
                }
                $jobTitle = $null
                if ($account.JobTitle -ne '') {
                    $jobTitle = $account.JobTitle
                }
                $department = $null
                if ($account.Department -ne '') {
                    $department = $account.Department
                }

                $adAccount = Set-ADUser $existingAccountName `
                    -DisplayName $fullName `
                    -GivenName $firstName `
                    -Surname $lastName `
                    -SAMAccountName $accountName `
                    -UserPrincipalName $fullAccountName `
                    -EmployeeID $employeeID `
                    -Title $jobTitle `
                    -EmailAddress $fullAccountName `
                    -Department $department `
                    -Company "Starfleet District" `
                    -Description $jobTitle `
                    -Office $officeName `
                    -StreetAddress $streetAddress `
                    -City $city `
                    -State $state `
                    -PostalCode $postalCode `
                    -Country $country `
                    -OfficePhone $phone `
                    -PassThru

                # Set the user's manager if it was specified.
                if ($managerAccountName -ne '') {
                    $adAccount | Set-ADUser -Manager $managerAccountName
                }

                # Set the user's group membership.
                Set-ADGroupMembership $account

                if ($adAccount -ne $null) {
                    Write-Output ("`tAD account updated: {0}" -f $adAccount.UserPrincipalName)
                } else {
                    Write-Output "`tAD account update failed!"
                }
            } else {
                Write-Output "`tCouldn't find account in AD."
            }
        } else {
            Write-Output "`tInvalid parameter(s) supplied. Can't update AD account."
        }
    }
}


# -------------------- BEGIN SCRIPT --------------------

# ---------- IMPORT SOURCES ----------
$sor = Import-CSV -Path .\SOR.csv
$hr = Import-CSV -Path .\HR.csv
$sis = Import-CSV -Path .\SIS.csv
$offices = Import-CSV -Path .\Office.csv

# Process changes from each source.
Write-Output "----- Processing HR Changes -----"
$hr | ForEach-Object {
    $entry = $_
    $accountEntry = $sor | Where-Object { ($_.EmployeeID -eq $entry.EmployeeId) }
    if ($accountEntry -eq $null)
    {
        # Get the employee's manager's employee ID if specified.
        $managerEmployeeID = ''
        if ($_.ManagerID -ne '') {
            $managerEmployeeID = $_.ManagerID
            $manager = $sor | Where-Object { ($_.EmployeeID -eq $managerEmployeeID) }
            if ($manager -ne $null) {
                # The manager was found.
                $managerEmployeeID = $manager.AccountID
            }
        }

        # Add the employee to the System of Record.
        $newEmployee = [PSCustomObject]@{
            AccountID = Get-NextAccountID
            AccountType = "Employee"
            FirstName = $_.FirstName
            LastName = $_.LastName
            JobTitle = $_.JobTitle
            Department = $_.Department
            Office = $_.Office
            Phone = $_.Phone
            GradeLevel = ""
            ManagerID = $managerEmployeeID
            EmployeeID = $_.EmployeeID
            StudentID = ""
            Status = "Active"
        }
        $accountName = Create-AccountName $_.FirstName $_.LastName $sor
        if ($accountName -ne "") {
            # An account name was created.
            # Fill in the account name and e-mail address.
            $newEmployee | Add-Member AccountName $accountName
            $newEmployee | Add-Member Email "$accountName@scoe.info"
        }

        # Add the new employee's information.
        if ($sor -eq $null) {
            # The System of Record needs to be created before adding.
            $sor = @( $newEmployee )
        } else {
            # The System of Record exists, add the employee.
            $sor += $newEmployee
        }
        Write-Output ("Added new employee {0} {1}" -f $_.FirstName,$_.LastName)

        # Create any accounts associated with the employee.

        # AD
        New-IdmADAccount $newEmployee
        Set-IdmADAccount $newEmployee.AccountID $sor $offices

    } else {
        # Update the existing employee entry in the System of Record.
        # Skip deleted accounts.
        if ($_.Status -ne "Deleted") {
            Write-Output ("Checking employee {0} {1} for changes" -f $_.FirstName,$_.LastName)
            $changed = $false
            if ($_.FirstName -ne $accountEntry.FirstName) {
                $originalValue = $accountEntry.FirstName
                $accountEntry.FirstName = $_.FirstName
                Write-Output ("`tFirst Name: {0} => {1}" -f $originalValue,$_.FirstName)
                $changed = $true
            }
            if ($_.LastName -ne $accountEntry.LastName) {
                $originalValue = $accountEntry.LastName
                $accountEntry.LastName = $_.LastName
                Write-Output ("`tLast Name: {0} => {1}" -f $originalValue,$_.LastName)
                $changed = $true
            }
            if ($_.JobTitle -ne $accountEntry.JobTitle) {
                $originalValue = $accountEntry.JobTitle
                $accountEntry.JobTitle = $_.JobTitle
                Write-Output ("`tJob Title: {0} => {1}" -f $originalValue,$_.JobTitle)
                $changed = $true
            }
            if ($_.Department -ne $accountEntry.Department) {
                $originalValue = $accountEntry.Department
                $accountEntry.Department = $_.Department
                Write-Output ("`tDepartment {0} => {1}" -f $originalValue,$_.Department)
                $changed = $true
            }
            if ($_.Office -ne $accountEntry.Office) {
                $originalValue = $accountEntry.Office
                $accountEntry.Office = $_.Office
                Write-Output ("`tOffice: {0} => {1}" -f $originalValue,$_.Office)
                $changed = $true
            }
            if ($_.Phone -ne $accountEntry.Phone) {
                $originalValue = $accountEntry.Phone
                $accountEntry.Phone = $_.Phone
                Write-Output ("`tPhone: {0} => {1}" -f $originalValue,$_.Phone)
                $changed = $true
            }
            if ($_.ManagerID -ne $accountEntry.ManagerID) {
                $originalValue = $accountEntry.ManagerID
                $accountEntry.ManagerID = $_.ManagerID
                Write-Output ("`tManagerID: {0} => {1}" -f $originalValue,$_.ManagerID)
                $changed = $true
            }

            # Update any accounts associated with the employee.

            if ($changed -eq $true) {
                # AD
                Set-IdmADAccount $accountEntry.AccountID $sor $offices
            }
        }
    }
}

Write-Output "----- Processing SIS Changes -----"
$sis | ForEach-Object {
    $entry = $_
    $accountEntry = $sor | Where-Object { ($_.StudentID -eq $entry.StudentId) }
    if ($accountEntry -eq $null)
    {
        # Get the student's teacher's account ID if specified.
        $teacherAccountID = ''
        if ($_.TeacherID -ne '') {
            $teacherEmployeeID = $_.TeacherID
            $teacher = $sor | Where-Object { ($_.EmployeeID -eq $teacherEmployeeID) }
            if ($teacher -ne $null) {
                # The teacher was found.
                $teacherAccountID = $teacher.AccountID
            }
        }

        # Add the student to the System of Record.
        $newStudent = [PSCustomObject]@{
            AccountID = Get-NextAccountID
            AccountType = "Student"
            FirstName = $_.FirstName
            LastName = $_.LastName
            JobTitle = "Student at {0} - Grade {1}" -f $_.School,$_.GradeLevel
            Department = ""
            Office = $_.School
            Phone = ""
            GradeLevel = $_.GradeLevel
            ManagerID = $teacherAccountID
            EmployeeID = ""
            StudentID = $_.StudentID
            Status = "Active"
        }
        $accountName = Create-AccountName $_.FirstName $_.LastName $sor
        if ($accountName -ne "") {
            # An account name was created.
            # Fill in the account name and e-mail address.
            $newStudent | Add-Member AccountName $accountName
            $newStudent | Add-Member Email "$accountName@scoe.info"
        }

        # Add the new student's information.
        if ($sor -eq $null) {
            # The System of Record needs to be created before adding.
            $sor = @( $newStudent )
        } else {
            # The System of Record exists, add the student.
            $sor += $newStudent
            Write-Output ("Added new student {0} {1}" -f $_.FirstName,$_.LastName)
        }

        # Create any accounts associated with the student.

        # AD
        New-IdmADAccount $newStudent
        Set-IdmADAccount $newStudent.AccountID $sor $offices

    } else {
        # Update the existing student entry in the System of Record.
        # Skip deleted accounts.
        if ($_.Status -ne "Deleted") {
            Write-Output ("Checking student {0} {1} for changes" -f $_.FirstName,$_.LastName)
            $changed = $false
            $gradeOrSchoolChanged = $false
            if ($_.FirstName -ne $accountEntry.FirstName) {
                $originalValue = $accountEntry.FirstName
                $accountEntry.FirstName = $_.FirstName
                Write-Output ("`tFirst Name: {0} => {1}" -f $originalValue,$_.FirstName)
                $changed = $true
            }
            if ($_.LastName -ne $accountEntry.LastName) 
            {
                $originalValue = $accountEntry.LastName
                $accountEntry.LastName = $_.LastName
                Write-Output ("`tLast Name: {0} => {1}" -f $originalValue,$_.LastName)
                $changed = $true
            }
            if ($_.School -ne $accountEntry.Office) {
                $originalValue = $accountEntry.Office
                $accountEntry.Office = $_.School
                Write-Output ("`tOffice: {0} => {1}" -f $originalValue,$_.School)
                $gradeOrSchoolChanged = $true
                $changed = $true
            }
            if ($_.GradeLevel -ne $accountEntry.GradeLevel) {
                $originalValue = $accountEntry.GradeLevel
                $accountEntry.GradeLevel = $_.GradeLevel
                Write-Output ("`tGrade Level: {0} => {1}" -f $originalValue,$_.GradeLevel)
                $gradeOrSchoolChanged = $true
                $changed = $true
            }
            if ($_.TeacherID -ne $accountEntry.ManagerID) {
                $originalValue = $accountEntry.ManagerID
                $accountEntry.ManagerID = $_.TeacherID
                Write-Output ("`tManagerID: {0} => {1}" -f $originalValue,$_.TeacherID)
                $changed = $true
            }
            # Write the JobTitle if their School or GradeLevel changed.
            if ($gradeOrSchoolChanged) {
                $originalValue = $accountEntry.JobTitle
                $accountEntry.JobTitle = "Student at {0} - Grade {1}" -f $_.School,$_.GradeLevel
                Write-Output ("`tJob Title: {0} => {1}" -f $originalValue,$accountEntry.JobTitle)
            }
            
            # Update any accounts associated with the student.

            if ($changed -eq $true) {
                # AD
                Set-IdmADAccount $accountEntry.AccountID $sor $offices
            }
        }
    }
}

# Export the changes to System of Record File
$sor | Select-Object -Property AccountID,AccountType,AccountName,Email,FirstName,LastName,JobTitle,Department,Office,Phone,GradeLevel,ManagerID,EmployeeID,StudentID,Status,Action | Export-CSV -Path .\SOR.csv -NoTypeInformation

# ---------- ACTIONS ----------

# Check for action items within the System of Record.
Write-Output "----- Processing Action Items -----"
$sor | Where-Object { ($_.Action -ne "") } | ForEach-Object {
    $account = $_
    switch ($account.Action) {
        "Enable" {
            # Enable the account if disabled.
            if ($account.Status -eq "Disabled") {
                # AD
                Enable-ADAccount $account.AccountName
                Write-Output ("Account enabled - {0}" -f $account.AccountName)
            }
            $account.Status = "Active"
            $account.Action = ""
            break
        }
        "Disable" {
            # Disable the account if active.
            if ($account.Status -eq "Active") {
                # AD
                Disable-ADAccount $account.AccountName
                Write-Output ("Account disabled - {0}" -f $account.AccountName)
            }
            $account.Status = "Disabled"
            $account.Action = ""
            break
        }
        "Delete" {
            # Delete the account.
            #AD
            Remove-ADUser $account.AccountName -Confirm:$false
            Write-Output ("Account deleted - {0}" -f $account.AccountName)
            $account.Status = "Deleted"
            $account.Action = ""
            break
        }
        "Reset" {
            # Reset's the account's properties and group memberships from data within the System of Record.
            Write-Output ("Resetting - {0}" -f $account.AccountName)
            Set-IdmADAccount $account.AccountID $sor $offices
            $account.Action = ""
            break
        }
    }
}

# Export the changes to System of Record File
$sor | Select-Object -Property AccountID,AccountType,AccountName,Email,FirstName,LastName,JobTitle,Department,Office,Phone,GradeLevel,ManagerID,EmployeeID,StudentID,Status,Action | Export-CSV -Path .\SOR.csv -NoTypeInformation


# -------------------- END SCRIPT --------------------