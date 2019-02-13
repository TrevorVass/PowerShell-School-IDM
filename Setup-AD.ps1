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


# -------------------- BEGIN SCRIPT --------------------

# Create OU
New-ADOrganizationalUnit -Name "IDM" -Path "DC=scoe,DC=info" -ProtectedFromAccidentalDeletion $False

# Create Groups
New-ADGroup -Name "Archer Elementary Administrators" -DisplayName "Archer Elementary Administrators" -SamAccountName "archer-administrators" -GroupScope Global -GroupCategory Security -Description "Administrators at Jonathan Archer Elementary School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Archer Elementary Teachers" -DisplayName "Archer Elementary Teachers" -SamAccountName "archer-teachers" -GroupScope Global -GroupCategory Security -Description "Teachers at Jonathan Archer Elementary School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Archer Elementary Staff" -DisplayName "Archer Elementary Staff" -SamAccountName "archer-staff" -GroupScope Global -GroupCategory Security -Description "Staff at Jonathan Archer Elementary School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Archer Elementary Students" -DisplayName "Archer Elementary Students" -SamAccountName "archer-students" -GroupScope Global -GroupCategory Security -Description "Students at Jonathan Archer Elementary School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Erikson Middle Administrators" -DisplayName "Erikson Middle Administrators" -SamAccountName "erikson-administrators" -GroupScope Global -GroupCategory Security -Description "Administrators at Dr. Emory Erikson Middle School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Erikson Middle Teachers" -DisplayName "Erikson Middle Teachers" -SamAccountName "erikson-teachers" -GroupScope Global -GroupCategory Security -Description "Teachers at Dr. Emory Erikson Middle School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Erikson Middle Staff" -DisplayName "Erikson Middle Staff" -SamAccountName "erikson-staff" -GroupScope Global -GroupCategory Security -Description "Staff at Dr. Emory Erikson Middle School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Erikson Middle Students" -DisplayName "Erikson Middle Students" -SamAccountName "erikson-students" -GroupScope Global -GroupCategory Security -Description "Students at Dr. Emory Erikson Middle School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Cochran High Administrators" -DisplayName "Cochran High Administrators" -SamAccountName "cochran-administrators" -GroupScope Global -GroupCategory Security -Description "Administrators at Zefram Cochran High School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Cochran High Teachers" -DisplayName "Cochran High Teachers" -SamAccountName "cochran-teachers" -GroupScope Global -GroupCategory Security -Description "Teachers at Zefram Cochran High School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Cochran High Staff" -DisplayName "Cochran High Staff" -SamAccountName "cochran-staff" -GroupScope Global -GroupCategory Security -Description "Staff at Zefram Cochran High School" -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Cochran High Students" -DisplayName "Cochran High Students" -SamAccountName "cochran-students" -GroupScope Global -GroupCategory Security -Description "Students at Zefram Cochran High School" -Path "OU=IDM,DC=scoe,DC=info"

New-ADGroup -Name "Teachers" -DisplayName "Teachers" -SamAccountName "teachers" -GroupScope Global -GroupCategory Security -Description "Teachers at all schools" -Path "OU=IDM,DC=scoe,DC=info"
#Add-ADGroupMember teachers -Members archer-teachers,erikson-teachers,cochran-teachers

New-ADGroup -Name "Students" -DisplayName "Students" -SamAccountName "students" -GroupScope Global -GroupCategory Security -Description "Students at all schools" -Path "OU=IDM,DC=scoe,DC=info"
#Add-ADGroupMember students -Members archer-students,erikson-students,cochran-students

New-ADGroup -Name "School Administrators" -DisplayName "School Administrators" -SamAccountName "school-administrators" -GroupScope Global -GroupCategory Security -Description "Administrators at school sites." -Path "OU=IDM,DC=scoe,DC=info"
#Add-ADGroupMember school-administrators -Members archer-administrators,erikson-administrators,cochran-administrators

New-ADGroup -Name "District Administrators" -DisplayName "District Administrators" -SamAccountName "district-administrators" -GroupScope Global -GroupCategory Security -Description "Administrators at the district office." -Path "OU=IDM,DC=scoe,DC=info"

New-ADGroup -Name "District Staff" -DisplayName "District Staff" -SamAccountName "district-staff" -GroupScope Global -GroupCategory Security -Description "Staff at the district office." -Path "OU=IDM,DC=scoe,DC=info"

New-ADGroup -Name "Information Technology Managers" -DisplayName "Information Technology Managers" -SamAccountName "it-managers" -GroupScope Global -GroupCategory Security -Description "Managers of the IT department." -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Information Technology Engineers" -DisplayName "Information Technology Engineers" -SamAccountName "it-engineers" -GroupScope Global -GroupCategory Security -Description "Engineers within the IT department." -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Information Technology Technicians" -DisplayName "Information Technology Technicians" -SamAccountName "it-technicians" -GroupScope Global -GroupCategory Security -Description "Technicians within the IT department." -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Information Technology Developers" -DisplayName "Information Technology Developers" -SamAccountName "it-developers" -GroupScope Global -GroupCategory Security -Description "Developers within the IT department." -Path "OU=IDM,DC=scoe,DC=info"
New-ADGroup -Name "Information Technology" -DisplayName "Information Technology" -SamAccountName "it" -GroupScope Global -GroupCategory Security -Description "All members of the IT department." -Path "OU=IDM,DC=scoe,DC=info"
#Add-ADGroupMember it -Members it-managers,it-engineers,it-technicians,it-developers
