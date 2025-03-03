$clientId = "your_client_id"
$clientSecret = "your_client_secret"
$region = "mypurecloud.com"  # Change based on your Genesys region (e.g., mypurecloud.com, mypurecloud.ie)

# Encode credentials for Basic Auth
$base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$clientId`:$clientSecret"))

# Request access token
$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.$region/oauth/token" -Headers @{
    Authorization = "Basic $base64Auth"
    "Content-Type" = "application/x-www-form-urlencoded"
} -Body "grant_type=client_credentials"

$accessToken = $tokenResponse.access_token


# Import user emails from CSV
$usersEmails = Import-Csv -Path "UserEmails.csv"

$usersWithDIDs = @()

foreach ($user in $usersEmails) {
    $email = $user.Email

    $userResponse = Invoke-RestMethod -Method Get -Uri "https://api.$region/api/v2/users?email=$email&expand=primaryContactInfo" -Headers @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    $userData = $userResponse.entities | Select-Object id, name, primaryContactInfo

    $didNumber = $userData.primaryContactInfo | Where-Object { $_.mediaType -eq "PHONE" -and $_.type -eq "DID" } | Select-Object -ExpandProperty value

    $usersWithDIDs += [PSCustomObject]@{
        Email = $email
        Name  = $userData.name
        DID   = $didNumber
    }
}

# Save results to CSV
$usersWithDIDs | Export-Csv -Path "Users_DID_List.csv" -NoTypeInformation

Write-Host "User DID list exported to Users_DID_List.csv"

#Import CSV and then append information to our active directory 
##########################################################################

# Import the Genesys users with their DID numbers
$usersWithDIDs = Import-Csv -Path "Users_DID_List.csv"

# Log file for tracking updates
$logPath = "C:\Logs\AD_Update_Log.txt"

# Loop through each Genesys user and update their AD profile
foreach ($user in $usersWithDIDs) {
    $email = $user.UserPrincipalName  # Email from Genesys Cloud
    $didNumber = $user.DID

    if ($didNumber -and $email) {
        try {
            # Find the user in AD by their email (UserPrincipalName)
            $adUser = Get-ADUser -Filter { UserPrincipalName -eq $email } -Properties telephoneNumber
            
            if ($adUser) {
                # Update the telephone number in AD
                Set-ADUser -Identity $adUser.DistinguishedName -TelephoneNumber $didNumber
                Write-Host "Updated $($adUser.Name) ($email) with DID $didNumber" -ForegroundColor Green
                "$($adUser.Name) ($email) updated with DID $didNumber" | Out-File -Append -FilePath $logPath
            } else {
                Write-Host "User with email $email not found in AD" -ForegroundColor Red
                "User with email $email not found in AD" | Out-File -Append -FilePath $logPath
            }
        } catch {
            Write-Host "Error updating $email: $_" -ForegroundColor Yellow
            "Error updating $email: $_" | Out-File -Append -FilePath $logPath
        }
    }
}




# I want to look at this 

# Define Genesys Cloud API credentials
$clientId = "your_client_id"
$clientSecret = "your_client_secret"
$region = "mypurecloud.com"  # Adjust for your Genesys region

# Get OAuth token
$base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$clientId`:$clientSecret"))

$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.$region/oauth/token" -Headers @{
    Authorization = "Basic $base64Auth"
    "Content-Type" = "application/x-www-form-urlencoded"
} -Body "grant_type=client_credentials"

$accessToken = $tokenResponse.access_token

# Import users from Active Directory
$adUsers = Get-ADUser -Filter * -Properties UserPrincipalName, telephoneNumber

# Log file path
$logPath = "C:\Logs\AD_Update_Log.txt"

foreach ($adUser in $adUsers) {
    $email = $adUser.UserPrincipalName

    if ($email) {
        try {
            # Query Genesys Cloud API for the user's DID using email
            #this get request shows us everything under the contact information section of a genesys profile as a Json. 
            $userResponse = Invoke-RestMethod -Method Get -Uri "https://api.$region/api/v2/users?email=$email&expand=primaryContactInfo" -Headers @{
                Authorization = "Bearer $accessToken"
                "Content-Type" = "application/json"
            }
            

            # Extract user data from Genesys
            
            $genesysUser = $userResponse.entities | Select-Object id, name, primaryContactInfo
            $didNumber = $genesysUser.primaryContactInfo | Where-Object { $_.mediaType -eq "PHONE" -and $_.type -eq "DID" } | Select-Object -ExpandProperty value

            if ($didNumber) {
                # Update telephoneNumber in AD
                Set-ADUser -Identity $adUser.DistinguishedName -TelephoneNumber $didNumber
                Write-Host "Updated $($adUser.Name) ($email) with DID $didNumber" -ForegroundColor Green
                "$($adUser.Name) ($email) updated with DID $didNumber" | Out-File -Append -FilePath $logPath
            } else {
                Write-Host "No DID found for $email in Genesys" -ForegroundColor Yellow
                "No DID found for $email in Genesys" | Out-File -Append -FilePath $logPath
            }
        } catch {
            Write-Host "Error updating $email: $_" -ForegroundColor Red
            "Error updating $email: $_" | Out-File -Append -FilePath $logPath
        }
    }
}

Write-Host "AD update process completed. Log file saved at $logPath"