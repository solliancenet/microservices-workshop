# Creating a Solliance University Lab

This repo has all the necessary items and details to create a Solliance University lab.

## Lab Documentation

All lab steps should be in GitHub markdown language. The progress of the labs is driven by the `masterdoc.json` file.  You can do whatever you like in the lab documents, just as long as you ensure you have created and point to the outline document in your lab template.

## Lab Setup

Each lab will require the following items:

- Initial ARM template deployment file
- A parameters file
- A VM install script

Optionally, you can have a Policy and a custom RBAC file as well:

- policy.json
- rbac.json

### Initial ARM template

The initial ARM template will allocate a virtual machine.  It is within this virtual machine that you are expected to perform all the other setup required for the labs.  

This is accomplished by executing the VM Install PowerShell script.

### VM Install Script

This is where you will install any necessary items you may need into the VM and then deploy your main ARM template for your lab.

## Spektra Setup

Once you have the ARM template and necessary lab documentation you can create a lab template and on-demand lab in Spektra.

### Templates

1. Browse to the Spektra Portal and select **Templates** page - https://admin.cloudlabs.ai/#/home/template
2. Select **+ADD**
3. Enter all the required information:

   - Name : Name of the workshop
   - Cloud Usage Type
   - Code
   - Subscription Type
   - Description
   - Owner Email
   - Deployment Plan
   - Region : Regions that support your deployment

4. Select **SUBMIT**

### On-Demand Labs

1. Browse to the **On Demand Labs** page
2. Select **+ADD ON DEMAND LAB**
3. Type the workshop name, then select the template, most of the lab information will be populated from the template.
4. Enter the required information:

   - Region : Regions that support your deployment
   - Status
   - Approval
   - Duration (in Minutes)
   - Expiry Date
   - Subscription Group
   - Owner Email

5. Select the **Hot Instances** checkbox
6. Select **SUBMIT**

## Hot Instances

1. You can test your deployment using the `Hot labs` feature of Spektra.
2. Browse to the **On Demand Labs** page
3. For the workshop, select the **Hot instances** icon
4. Select **+ADD**
5. For the number, type **1**
6. Select **ADD**

## Registration

Spektra has several ways to provide registration for a lab.

- TODO

## FAQs

- None

## Reference Links

- [Azure Portal](https://portal.azure.com)
- [Spektra Admin](https://admin.cloudlabs.ai/)
