package com.Aura.Homes.repository;

import com.Aura.Homes.entity.Parent;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ParentRepository extends JpaRepository<Parent, Long> {

    Parent findByEmail(String email);


}
