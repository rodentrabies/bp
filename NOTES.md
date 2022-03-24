# Notes & Ideas

## Referencing syntax

Simple colon-separated (period-separated?) disambiguated syntax for
referencing any Bitcoin chain data items:

- blocks
  - height
    `727326`
  - hash
    `0000000000000000000918db3142fc4ccea865edb9a9f0c05f5a1b507fd7182a`

- transactions
  - block : index
    `727326:2`
  - block : txid (redundant; is this ok?)
    `727326:10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5`
    if transaction is referenced with txid, block can be omitted
    `10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5`
  
- output
  - tx + oindex
    `727236:2:1`
    this form is compatible with LN out points
    `10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5:1`

- input
  - tx : iindex + `i`
    `727236:2:0i`
    `10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5:0i`

- witness
  - tx : windex + `w`
    `727236:2:0w`
    `10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5:0w`

- witness item
  - witness : wiindex
    `727236:2:0w:0`
    `10a4f97009323150f6baa36442cfdf0cf829cd6d2d00cacdfa832f9bbb8c6db5:0w:0`
