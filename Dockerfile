
# FROM golang:$VERSION
# LABEL maintainer="SanjeevNataraj"
# COPY ../employee /employee
# RUN echo $VERSION > golang_image_version
# RUN go build .

# # WORKDIR /go/src/github.com/employee
# # absolute directory frontla /
# # ADD ..\employee /go/src/github.com/employee/ 
# CMD "go run employee.go"

# EXPOSE 3000/tcp

FROM golang:1.14-alpine AS build

# Install tools required for project
# Run `docker build --no-cache .` to update dependencies
RUN apk add --no-cache git
RUN go get github.com/golang/dep/cmd/dep

# List project dependencies with Gopkg.toml and Gopkg.lock
# These layers are only re-built when Gopkg files are updated
COPY go.sum go.mod /go/src/employee/
WORKDIR /go/src/employee/
# Install library dependencies
RUN go mod download

# Copy the entire project and build it
# This layer is rebuilt when a file changes in the project directory
COPY . /go/src/employee/
RUN go build -o employee

# This results in a single layer image
# FROM scratch
# COPY --from=build /go/bin /go/bin
# ENTRYPOINT ["go/bin"]
CMD ["./employee"]