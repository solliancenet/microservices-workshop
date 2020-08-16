# Virtual Dev Intersection Cloud Native Apps Workshop

To deliver a microservices solution there are many aspects to consider from design through production deployment. Developing applications for a microservices architecture requires an approach to development that requires attention to microservices design principles, and a strategy that early on influences developer workflows. Early in your adoption of a microservices approach it is critical to pull together a shared understanding for development practices, DevOps practices, and workflows that involve everyone from developer through to operations in production. The workshop will take you through developing for a microservices architecture on Azure from design through deployment and delivery. We’ll cover some common design principles and challenges you'll face making decisions about microservices domains, followed by a tour of development fundamentals for Docker and ASP.NET Core where we’ll show how to handle early instrumentation, configuration, secrets, health checks and other considerations related to load balancing containerized applications. Beyond the development aspects, the workshop will cover DevOps delivery practices with Azure DevOps leveraging Azure Container Registry (ACR) and delivering to your Azure environment. We’ll focus on some common practices for large scale microservices solutions in Azure including overall solution topology, networking, and security. Azure resources covered in this discussion will include Traffic Manager, Front Door, Application Gateway / Web Application Firewall (WAF), Azure Kubernetes Service (AKS), Azure Container Registry (ACR), and securely connecting microservices to data storage such as SQL Database or Cosmos DB. You’ll learn approaches to managing secrets, secure networking practices, monitoring and logging. The focus of the workshop is to provide a holistic understanding of design, development and delivery concerns for a microservices solution - and help you up your game by sharing insights into real developer and operational experiences developing ASP.NET Core, and Docker-based microservices solutions delivered to Azure.

## Schedule

The following are the labs you will perform on each day.

### Day 1

- [Lab 1: Proof of concept deployment](./01_Lab01.md)
- [Lab 2: Deploy the solution to Azure Kubernetes Service](./01_Lab02.md)
- [Lab 3: Scale the application and test HA](./02_Lab01.md)
- [Lab 4: Services and Routing Application Traffic](./02_Lab02.md)

## Reference Links

The following links are helpful as reference for the topics discussed during this workshop.

- Azure Kubernetes Service (AKS)
- Azure Container Instances
- Azure Container Registry
