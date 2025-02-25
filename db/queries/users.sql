-- name: CreateUser :one
INSERT INTO users (
    id,
    email,
    name,
    provider,
    provider_user_id,
    role,
    permissions
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *;

-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1;