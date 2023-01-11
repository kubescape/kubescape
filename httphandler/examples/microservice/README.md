# Kubescape as a microservice

1. Deploy kubescape microservice
    ```bash
    kubectl apply -f ks-deployment.yaml
    ```
    > **Note**  
    > Make sure the configurations suit your cluster (e.g. `serviceType`, namespace, etc.)

2. Trigger scan
    ```bash
    curl --header "Content-Type: application/json" \
    --request POST \
    --data '{"account":"XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX","hostScanner":true}' \
    http://127.0.0.1:8080/v1/scan
    ```

3. Get results
    ```bash
    curl --request GET http://127.0.0.1:8080/v1/results -o results.json
    ```
