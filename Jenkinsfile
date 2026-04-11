pipeline {
    agent any

    // WHY parameters here too?
    // These mirror the Jenkins job parameters.
    // Allows the Jenkinsfile to know which environment
    // and branch was selected when triggered.
    parameters {
        choice(name: 'ENVIRONMENT', choices: ['dev', 'prod'], description: 'Environment to deploy to')
        string(name: 'BRANCH', defaultValue: 'main', description: 'Branch to deploy from')
    }

    environment {
        // GHCR image name
        IMAGE_NAME = 'ghcr.io/mehulbansal2003/railway-auth-service'
        IMAGE_TAG = "${BUILD_NUMBER}"  // unique tag per build

        // Backend EC2 details — we'll use different IPs for dev/prod
        BACKEND_USER = 'ubuntu'
    }

    stages {

        stage('Checkout') {
            steps {
                // WHY? Pull the exact branch the user selected
                git credentialsId: 'github-credentials',
                    url: 'https://github.com/mehulbansal2003/railway-auth-service',
                    branch: "${params.BRANCH}"
            }
        }

        stage('Build JAR') {
            steps {
                sh 'java -version'
                sh 'mvn --version'
                withCredentials([usernamePassword(
                    credentialsId: 'github-credentials',
                    usernameVariable: 'GITHUB_ACTOR',
                    passwordVariable: 'GITHUB_TOKEN'
                )]) {
                    sh '''
                        mvn clean package -DskipTests \
                            -s .mvn/settings.xml \
                            -Dgithub.actor=${GITHUB_ACTOR} \
                            -Dgithub.token=${GITHUB_TOKEN} \
                            --no-transfer-progress
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    withCredentials([usernamePassword(
                        credentialsId: 'github-credentials',
                        usernameVariable: 'GITHUB_ACTOR',
                        passwordVariable: 'GITHUB_TOKEN'
                    )]) {
                        sh """
                            docker build \
                              --platform linux/amd64 \
                              --build-arg GITHUB_ACTOR=${GITHUB_ACTOR} \
                              --build-arg GITHUB_TOKEN=${GITHUB_TOKEN} \
                              -t ${IMAGE_NAME}:${IMAGE_TAG} \
                              -t ${IMAGE_NAME}:latest \
                              .
                        """
                    }
                }
            }
        }

        stage('Push to GHCR') {
            steps {
                script {
                    // WHY withCredentials?
                    // Safely injects the GHCR token without exposing it in logs
                    withCredentials([usernamePassword(
                        credentialsId: 'ghcr-credentials',
                        usernameVariable: 'GHCR_USER',
                        passwordVariable: 'GHCR_TOKEN'
                    )]) {
                        sh """
                            echo \${GHCR_TOKEN} | docker login ghcr.io -u \${GHCR_USER} --password-stdin
                            docker push ${IMAGE_NAME}:${IMAGE_TAG}
                            docker push ${IMAGE_NAME}:latest
                        """
                    }
                }
            }
        }

        stage('Deploy to EC2') {
            steps {
                script {
                    def backendHost = params.ENVIRONMENT == 'prod'
                        ? 'YOUR_PROD_EC2_PRIVATE_IP'
                        : 'YOUR_DEV_EC2_PRIVATE_IP'

                    def containerName = params.ENVIRONMENT == 'prod'
                        ? 'railtick-auth-prod'
                        : 'railtick-auth-dev'

                    def sshCredential = params.ENVIRONMENT == 'prod'
                        ? 'prod-ec2-ssh'
                        : 'dev-ec2-ssh'

                    sshagent([sshCredential]) {
                        sh """
                            ssh -o StrictHostKeyChecking=no ubuntu@${backendHost} '
                                docker pull ${IMAGE_NAME}:latest &&
                                docker stop ${containerName} || true &&
                                docker rm ${containerName} || true &&
                                docker run -d \
                                    --name ${containerName} \
                                    --env-file /home/ubuntu/railtick/.env \
                                    -p 8080:8080 \
                                    ${IMAGE_NAME}:latest
                            '
                        """
                    }
                }
            }
        }
    }

    post {
        success {
            echo "✅ Deployed ${IMAGE_NAME}:${IMAGE_TAG} to ${params.ENVIRONMENT}"
        }
        failure {
            echo "❌ Deployment failed!"
        }
    }
}
