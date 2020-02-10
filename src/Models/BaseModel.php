<?php

namespace DeviceCookies\Models;

abstract class BaseModel
{
    /**
     * @var \PDO
     */
    protected $Dbh;

    /**
     * @var \PDOStatement
     */
    protected $Sth;

    /**
     * Class constructor.
     */
    public function __construct(\PDO $dbh)
    {
        $this->Dbh = $dbh;
    }

    /**
     * Delete data from DB table.
     *
     * @see https://github.com/doctrine/dbal/blob/master/lib/Doctrine/DBAL/Connection.php#L643
     * @param string $tableName The table name. This table name will NOT auto add prefix.
     * @param array $identifier The identifier for use in `WHERE` statement.
     * @return bool Return PDOStatement::execute(). Return `true` on success, `false` for otherwise.
     * @throws \InvalidArgumentException Throw the error if `$identifier` is incorrect value.
     */
    public function delete(string $tableName, array $identifier)
    {
        if (empty($identifier)) {
            throw new \InvalidArgumentException(
                'The argument $identifier is required associative array column - value pairs.'
            );
        }
        $columns = [];
        $placeholders = [];
        $values = [];
        $conditions = [];
        foreach ($identifier as $columnName => $value) {
            $columns[] = '`' . $columnName . '`';
            $conditions[] = '`' . $columnName . '` = ?';
            $values[] = $value;
        }// endforeach;
        unset($columnName, $value);
        $sql = 'DELETE FROM `' . $tableName . '` WHERE ' . implode(' AND ', $conditions);
        $this->Sth = $this->Dbh->prepare($sql);
        unset($columns, $placeholders, $sql);
        return $this->Sth->execute($values);
    }

    /**
     * Insert data into DB table.
     *
     * @see https://github.com/doctrine/dbal/blob/master/lib/Doctrine/DBAL/Connection.php#L749
     * @param string $tableName The table name. This table name will NOT auto add prefix.
     * @param array $data The associative array where column name is the key and its value is the value pairs.
     * @return bool Return PDOStatement::execute(). Return `true` on success, `false` for otherwise.
     * @throws \InvalidArgumentException Throw the error if `$data` is invalid.
     */
    public function insert(string $tableName, array $data): bool
    {
        if (empty($data)) {
            throw new \InvalidArgumentException(
                'The argument $data is required associative array column - value pairs.'
            );
        }
        $columns = [];
        $placeholders = [];
        $values = [];
        foreach ($data as $columnName => $value) {
            $columns[] = '`' . $columnName . '`';
            $placeholders[] = '?';
            $values[] = $value;
        }// endforeach;
        unset($columnName, $value);
        $sql = 'INSERT INTO `' . $tableName . '` (' . implode(', ', $columns) . ') VALUES ('
            . implode(', ', $placeholders) . ')';
        $this->Sth = $this->Dbh->prepare($sql);
        unset($columns, $placeholders, $sql);
        return $this->Sth->execute($values);
    }

    /**
     * Get PDO statement after called `insert()`, `update()`, `delete()`.
     *
     * @return \PDOStatement|null Return `\PDOStatement` object if exists, `null` if not exists.
     */
    public function PDOStatement()
    {
        return $this->Sth;
    }

    /**
     * Update data into DB table.
     *
     * @see https://github.com/doctrine/dbal/blob/master/lib/Doctrine/DBAL/Connection.php#L714
     * @param string $tableName The table name. This table name will NOT auto add prefix.
     * @param array $data The associative array where column name is the key and its value is the value pairs.
     * @param array $identifier The identifier for use in `WHERE` statement.
     * @return bool Return PDOStatement::execute(). Return `true` on success, `false` for otherwise.
     * @throws \InvalidArgumentException Throw the error if `$data` or `$identifier` is incorrect value.
     */
    public function update(string $tableName, array $data, array $identifier): bool
    {
        if (empty($data)) {
            throw new \InvalidArgumentException(
                'The argument $data is required associative array column - value pairs.'
            );
        }
        if (empty($identifier)) {
            throw new \InvalidArgumentException(
                'The argument $identifier is required associative array column - value pairs.'
            );
        }
        $columns = [];
        $placeholders = [];
        $values = [];
        $conditions = [];
        foreach ($data as $columnName => $value) {
            $columns[] = '`' . $columnName . '`';
            $placeholders[] = '`' . $columnName . '` = ?';
            $values[] = $value;
        }// endforeach;
        unset($columnName, $value);
        foreach ($identifier as $columnName => $value) {
            $columns[] = '`' . $columnName . '`';
            $conditions[] = '`' . $columnName . '` = ?';
            $values[] = $value;
        }// endforeach;
        unset($columnName, $value);
        $sql = 'UPDATE `' . $tableName . '` SET ' . implode(', ', $placeholders) . ' WHERE '
            . implode(' AND ', $conditions);
        $this->Sth = $this->Dbh->prepare($sql);
        unset($columns, $placeholders, $sql);
        return $this->Sth->execute($values);
    }
}
