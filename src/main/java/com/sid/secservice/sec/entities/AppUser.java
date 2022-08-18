package com.sid.secservice.sec.entities;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Entity
@Data @NoArgsConstructor @AllArgsConstructor
public class AppUser {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) // ignore this field in the getters, and only we can write on it
    private String password;

    @ManyToMany(fetch = FetchType.EAGER) // at the time we load the user we load automatically its roles. in the mode LAZY we load the user with one request then we load its roles with another request
    private Collection<AppRole> appRoles = new ArrayList<>(); // if we have EAGER mode, it is recommended to initialise the collection with arrayList
}
