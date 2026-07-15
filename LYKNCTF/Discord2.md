# Discord 2 Challenge

It was stated that Discord 2 is similar to Discord 1. So I started by peering through all the usernames. Then one username was online, going by the name of @regulus. Their status stated that the "LYKNCTF Flag is here". I clicked on the profile and attached was a discord link directing me to a server called discord 2.

On the Discord2 server, one of the channels contains a clue. The server also provides several commands, including `/start`, `/profile {username}`, `/recovery {token}`, and `/submit {wordlist}`.

The objective is to recover the wordlist needed to obtain the flag. By examining the chat history images across the different channels, we can piece together the recovery token:

`i_love_you_huhu`

Using this token with the `/recovery` command reveals the keyword:

`1h4nk5_f0r_pl4y1ng`

We then submit it using:

`/submit 1h4nk5_f0r_pl4y1ng`

This returns the flag:

`LYKNCTF{1s_th1s_ch4ll3ng3_h4rd3r_th4n_discord1??????????}`
