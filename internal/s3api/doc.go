// Package s3api implements HTTP routing with S3 semantics and the XML wire types.
//
// Routing cannot be expressed as plain path matching: S3 distinguishes operations by
// method, query parameters (?uploads, ?partNumber=, ?list-type=2) and headers
// (x-amz-copy-source) as much as by path.
package s3api
